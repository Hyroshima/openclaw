import {
  getChannelPlugin,
  resolveChannelApprovalCapability,
} from "../../channels/plugins/index.js";
import type { ChannelId } from "../../channels/plugins/types.public.js";
import { normalizeChannelId } from "../../channels/registry.js";
import { readConfigFileSnapshot } from "../../config/config.js";
import { logVerbose } from "../../globals.js";
import { isApprovalNotFoundError } from "../../infra/approval-errors.js";
import { resolveApprovalOverGateway } from "../../infra/approval-gateway-resolver.js";
import { resolveApprovalCommandAuthorization } from "../../infra/channel-approval-auth.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { normalizeLowercaseStringOrEmpty } from "../../shared/string-coerce.js";
import { resolveChannelAccountId } from "./channel-context.js";
import {
  rejectNonOwnerCommand,
  rejectUnauthorizedCommand,
  requireCommandFlagEnabled,
  requireGatewayClientScope,
} from "./command-gates.js";
import type {
  CommandHandler,
  CommandHandlerResult,
  HandleCommandsParams,
} from "./commands-types.js";
import { applyAllowlistConfigMutation, AutoReplyConfigMutationError } from "./config-mutations.js";
import { resolveConfigWriteDeniedText } from "./config-write-authorization.js";

const COMMAND_REGEX = /^\/?approve(?:\s|$)/i;
const FOREIGN_COMMAND_MENTION_REGEX = /^\/approve@([^\s]+)(?:\s|$)/i;

const DECISION_ALIASES: Record<string, "allow-once" | "allow-always" | "deny"> = {
  allow: "allow-once",
  once: "allow-once",
  "allow-once": "allow-once",
  allowonce: "allow-once",
  always: "allow-always",
  "allow-always": "allow-always",
  allowalways: "allow-always",
  deny: "deny",
  reject: "deny",
  block: "deny",
};

type ParsedApproveCommand =
  | { ok: true; id: string; decision: "allow-once" | "allow-always" | "deny" }
  | { ok: false; error: string };

const APPROVE_USAGE_TEXT =
  "Usage: /approve <id> <decision> (see the pending approval message for available decisions)";

function parseApproveCommand(raw: string): ParsedApproveCommand | null {
  const trimmed = raw.trim();
  if (FOREIGN_COMMAND_MENTION_REGEX.test(trimmed)) {
    return { ok: false, error: "❌ This /approve command targets a different Telegram bot." };
  }
  const commandMatch = trimmed.match(COMMAND_REGEX);
  if (!commandMatch) {
    return null;
  }
  const rest = trimmed.slice(commandMatch[0].length).trim();
  if (!rest) {
    return { ok: false, error: APPROVE_USAGE_TEXT };
  }
  const tokens = rest.split(/\s+/).filter(Boolean);
  if (tokens.length < 2) {
    return { ok: false, error: APPROVE_USAGE_TEXT };
  }

  const first = normalizeLowercaseStringOrEmpty(tokens[0]);
  const second = normalizeLowercaseStringOrEmpty(tokens[1]);

  if (DECISION_ALIASES[first]) {
    return {
      ok: true,
      decision: DECISION_ALIASES[first],
      id: tokens.slice(1).join(" ").trim(),
    };
  }
  if (DECISION_ALIASES[second]) {
    return {
      ok: true,
      decision: DECISION_ALIASES[second],
      id: tokens[0],
    };
  }
  return { ok: false, error: APPROVE_USAGE_TEXT };
}

function buildResolvedByLabel(params: Parameters<CommandHandler>[0]): string {
  const channel = params.command.channel;
  const sender = params.command.senderId ?? "unknown";
  return `${channel}:${sender}`;
}

function formatApprovalSubmitError(error: unknown): string {
  return formatErrorMessage(error);
}

type ApprovalMethod = "exec.approval.resolve" | "plugin.approval.resolve";

function resolveApprovalMethods(params: {
  approvalId: string;
  execAuthorization: ReturnType<typeof resolveApprovalCommandAuthorization>;
  pluginAuthorization: ReturnType<typeof resolveApprovalCommandAuthorization>;
}): ApprovalMethod[] {
  if (params.approvalId.startsWith("plugin:")) {
    return params.pluginAuthorization.authorized ? ["plugin.approval.resolve"] : [];
  }
  if (params.execAuthorization.authorized && params.pluginAuthorization.authorized) {
    return ["exec.approval.resolve", "plugin.approval.resolve"];
  }
  if (params.execAuthorization.authorized) {
    return ["exec.approval.resolve"];
  }
  if (params.pluginAuthorization.authorized) {
    return ["plugin.approval.resolve"];
  }
  return [];
}

function resolveApprovalAuthorizationError(params: {
  approvalId: string;
  execAuthorization: ReturnType<typeof resolveApprovalCommandAuthorization>;
  pluginAuthorization: ReturnType<typeof resolveApprovalCommandAuthorization>;
}): string {
  if (params.approvalId.startsWith("plugin:")) {
    return (
      params.pluginAuthorization.reason ?? "❌ You are not authorized to approve this request."
    );
  }
  return (
    params.execAuthorization.reason ??
    params.pluginAuthorization.reason ??
    "❌ You are not authorized to approve this request."
  );
}

type ParsedAllowlistApproveCommand =
  | { ok: true; entry: string; group: string; groupExplicit: boolean }
  | { ok: false; error: string };

type AllowlistAccessGroups = {
  groups: readonly string[];
  defaultGroup: string;
};

function parseAllowlistApproveCommand(
  raw: string,
  accessGroups: AllowlistAccessGroups,
): ParsedAllowlistApproveCommand | null {
  const trimmed = raw.trim();
  const commandMatch = trimmed.match(COMMAND_REGEX);
  if (!commandMatch) {
    return null;
  }
  const tokens = trimmed.slice(commandMatch[0].length).trim().split(/\s+/).filter(Boolean);
  if (tokens.length < 1 || tokens.length > 2) {
    return null;
  }
  const entry = tokens[0]?.trim();
  if (!entry) {
    return null;
  }
  const groupExplicit = tokens[1] !== undefined;
  const group = normalizeLowercaseStringOrEmpty(tokens[1] ?? accessGroups.defaultGroup);
  if (!group || !accessGroups.groups.includes(group)) {
    return {
      ok: false,
      error: `⚠️ Invalid allowlist group. Use one of: ${accessGroups.groups.join(", ")}.`,
    };
  }
  return { ok: true, entry, group, groupExplicit };
}

function resolveCommandChannelId(params: HandleCommandsParams): ChannelId | undefined {
  return params.command.channelId ?? normalizeChannelId(params.command.channel) ?? undefined;
}

async function handleAllowlistApproveCommand(params: {
  commandParams: HandleCommandsParams;
  channelId: ChannelId;
  accountId?: string | null;
  accessGroups: AllowlistAccessGroups;
}): Promise<CommandHandlerResult | null> {
  const plugin = getChannelPlugin(params.channelId);
  const parsed = parseAllowlistApproveCommand(
    params.commandParams.command.commandBodyNormalized,
    params.accessGroups,
  );
  if (!parsed) {
    return null;
  }
  if (!parsed.ok) {
    return { shouldContinue: false, reply: { text: parsed.error } };
  }

  const unauthorized = rejectUnauthorizedCommand(params.commandParams, "/approve allowlist");
  if (unauthorized) {
    return unauthorized;
  }
  const nonOwner = rejectNonOwnerCommand(params.commandParams, "/approve allowlist");
  if (nonOwner) {
    return nonOwner;
  }
  const missingAdminScope = requireGatewayClientScope(params.commandParams, {
    label: "/approve allowlist",
    allowedScopes: ["operator.admin"],
    missingText: "❌ /approve <sender> requires operator.admin for gateway clients.",
  });
  if (missingAdminScope) {
    return missingAdminScope;
  }
  const disabled = requireCommandFlagEnabled(params.commandParams.cfg, {
    label: "/approve allowlist edits",
    configKey: "config",
    disabledVerb: "are",
  });
  if (disabled) {
    return disabled;
  }
  const applyConfigEdit = plugin?.allowlist?.applyConfigEdit;
  if (!applyConfigEdit) {
    return {
      shouldContinue: false,
      reply: { text: `⚠️ ${params.channelId} does not support grouped allowlist approvals.` },
    };
  }

  const snapshot = await readConfigFileSnapshot();
  if (!snapshot.valid || !snapshot.parsed || typeof snapshot.parsed !== "object") {
    return {
      shouldContinue: false,
      reply: { text: "⚠️ Config file is invalid; fix it before using /approve allowlist." },
    };
  }
  const parsedConfig = structuredClone(snapshot.parsed as Record<string, unknown>);
  const editResult = await applyConfigEdit({
    cfg: params.commandParams.cfg,
    parsedConfig,
    accountId: params.accountId,
    scope: "dm",
    action: "add",
    entry: parsed.entry,
    accessGroup: parsed.group,
    accessGroupExplicit: parsed.groupExplicit,
  });
  if (!editResult) {
    return {
      shouldContinue: false,
      reply: { text: `⚠️ ${params.channelId} does not support DM allowlist approvals.` },
    };
  }
  if (editResult.kind === "invalid-entry") {
    return { shouldContinue: false, reply: { text: "⚠️ Invalid allowlist approval target." } };
  }
  const deniedText = resolveConfigWriteDeniedText({
    cfg: params.commandParams.cfg,
    channel: params.commandParams.command.channel,
    channelId: params.channelId,
    accountId: params.accountId ?? undefined,
    gatewayClientScopes: params.commandParams.ctx.GatewayClientScopes,
    target: editResult.writeTarget,
  });
  if (deniedText) {
    return { shouldContinue: false, reply: { text: deniedText } };
  }

  if (editResult.changed) {
    try {
      await applyAllowlistConfigMutation({
        cfg: params.commandParams.cfg,
        accountId: params.accountId,
        scope: "dm",
        action: "add",
        entry: parsed.entry,
        accessGroup: parsed.group,
        accessGroupExplicit: parsed.groupExplicit,
        applyConfigEdit,
      });
    } catch (error) {
      if (error instanceof AutoReplyConfigMutationError) {
        return { shouldContinue: false, reply: { text: `⚠️ ${error.message}` } };
      }
      throw error;
    }
  }

  if (!editResult.changed) {
    return { shouldContinue: false, reply: { text: "✅ Already allowlisted." } };
  }
  if (editResult.accessGroupChanged) {
    const previousGroup = editResult.accessGroupChanged.from ?? "unassigned";
    return {
      shouldContinue: false,
      reply: {
        text: `DM allowlist group updated (${previousGroup} -> ${editResult.accessGroupChanged.to}): ${editResult.pathLabel}.`,
      },
    };
  }
  return {
    shouldContinue: false,
    reply: {
      text: `✅ DM allowlist approved (${parsed.group}): ${editResult.pathLabel}.`,
    },
  };
}
export const handleApproveCommand: CommandHandler = async (params, allowTextCommands) => {
  if (!allowTextCommands) {
    return null;
  }
  const normalized = params.command.commandBodyNormalized;
  const parsed = parseApproveCommand(normalized);
  if (!parsed) {
    return null;
  }
  const effectiveAccountId = resolveChannelAccountId({
    cfg: params.cfg,
    ctx: params.ctx,
    command: params.command,
  });
  const commandChannelId = resolveCommandChannelId(params);
  const channelPlugin = commandChannelId
    ? getChannelPlugin(commandChannelId)
    : getChannelPlugin(params.command.channel);

  if (!parsed.ok) {
    const accessGroups = channelPlugin?.allowlist?.accessGroups;
    if (commandChannelId && accessGroups) {
      const allowlistResult = await handleAllowlistApproveCommand({
        commandParams: params,
        channelId: commandChannelId,
        accountId: effectiveAccountId,
        accessGroups,
      });
      if (allowlistResult) {
        return allowlistResult;
      }
    }
    return { shouldContinue: false, reply: { text: parsed.error } };
  }

  const isPluginId = parsed.id.startsWith("plugin:");
  const approvalCapability = resolveChannelApprovalCapability(channelPlugin);
  const approveCommandBehavior = approvalCapability?.resolveApproveCommandBehavior?.({
    cfg: params.cfg,
    accountId: effectiveAccountId,
    senderId: params.command.senderId,
    approvalKind: isPluginId ? "plugin" : "exec",
  });
  if (approveCommandBehavior?.kind === "ignore") {
    return { shouldContinue: false };
  }
  if (approveCommandBehavior?.kind === "reply") {
    return { shouldContinue: false, reply: { text: approveCommandBehavior.text } };
  }
  const execApprovalAuthorization = resolveApprovalCommandAuthorization({
    cfg: params.cfg,
    channel: params.command.channel,
    accountId: effectiveAccountId,
    senderId: params.command.senderId,
    kind: "exec",
  });
  const pluginApprovalAuthorization = resolveApprovalCommandAuthorization({
    cfg: params.cfg,
    channel: params.command.channel,
    accountId: effectiveAccountId,
    senderId: params.command.senderId,
    kind: "plugin",
  });
  const hasExplicitApprovalAuthorization =
    (execApprovalAuthorization.explicit && execApprovalAuthorization.authorized) ||
    (pluginApprovalAuthorization.explicit && pluginApprovalAuthorization.authorized);
  if (!params.command.isAuthorizedSender && !hasExplicitApprovalAuthorization) {
    logVerbose(
      `Ignoring /approve from unauthorized sender: ${params.command.senderId || "<unknown>"}`,
    );
    return { shouldContinue: false };
  }

  const missingScope = requireGatewayClientScope(params, {
    label: "/approve",
    allowedScopes: ["operator.approvals", "operator.admin"],
    missingText: "❌ /approve requires operator.approvals for gateway clients.",
  });
  if (missingScope) {
    return missingScope;
  }

  const resolvedBy = buildResolvedByLabel(params);
  const callApprovalMethod = async (method: ApprovalMethod): Promise<void> => {
    await resolveApprovalOverGateway({
      cfg: params.cfg,
      approvalId: parsed.id,
      decision: parsed.decision,
      senderId: params.command.senderId,
      ...(method === "plugin.approval.resolve" ? { resolveMethod: "plugin" as const } : {}),
      clientDisplayName: `Chat approval (${resolvedBy})`,
    });
  };

  const methods = resolveApprovalMethods({
    approvalId: parsed.id,
    execAuthorization: execApprovalAuthorization,
    pluginAuthorization: pluginApprovalAuthorization,
  });
  if (methods.length === 0) {
    return {
      shouldContinue: false,
      reply: {
        text: resolveApprovalAuthorizationError({
          approvalId: parsed.id,
          execAuthorization: execApprovalAuthorization,
          pluginAuthorization: pluginApprovalAuthorization,
        }),
      },
    };
  }

  for (const [index, method] of methods.entries()) {
    try {
      await callApprovalMethod(method);
      break;
    } catch (error) {
      const isLastMethod = index === methods.length - 1;
      if (!isApprovalNotFoundError(error) || isLastMethod) {
        return {
          shouldContinue: false,
          reply: { text: `❌ Failed to submit approval: ${formatApprovalSubmitError(error)}` },
        };
      }
    }
  }

  return {
    shouldContinue: false,
    reply: { text: `✅ Approval ${parsed.decision} submitted for ${parsed.id}.` },
  };
};
