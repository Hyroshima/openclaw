import { describe, expect, it } from "vitest";
import { telegramPlugin } from "./channel.js";

describe("telegram allowlist config edits", () => {
  it("updates the access group for an existing grouped DM allowFrom entry", () => {
    const parsedConfig = {
      channels: {
        telegram: {
          allowFrom: [{ number: "123456789", group: "restricted" }],
        },
      },
    };

    const result = telegramPlugin.allowlist?.applyConfigEdit?.({
      cfg: parsedConfig as never,
      parsedConfig,
      accountId: "default",
      scope: "dm",
      action: "add",
      entry: "123456789",
      accessGroup: "friends",
      accessGroupExplicit: true,
    });

    expect(result).toEqual(
      expect.objectContaining({
        kind: "ok",
        changed: true,
        accessGroupChanged: { from: "restricted", to: "friends" },
      }),
    );
    expect(parsedConfig.channels.telegram.allowFrom).toEqual([
      { number: "123456789", group: "friends" },
    ]);
  });
});
