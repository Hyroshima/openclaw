const GATEWAY_TOKEN = "YOUR_GATEWAY_TOKEN";
const OPERATOR_TARGET = "+1234567890";
const ACCESS_PHRASE = "Let me in";
const OPERATOR_CHANNEL = "whatsapp";

const handler = async (event: any) => {
  if (event.type !== "message" || event.action !== "pre-auth") return;

  const { senderId, senderName, content, channelId } = event.context;
  const trimmed = (content || "").trim();
  if (trimmed !== ACCESS_PHRASE) return;

  const name = senderName || "Unknown";

  const approveCmd = `/allowlist add dm --channel ${channelId} --group restricted ${senderId}`;
  const removeCmd = `/allowlist remove dm --channel ${channelId} ${senderId}`;

  const notification = [
    `⚡ *Access request received*`,
    ``,
    `📱 ID: ${senderId}`,
    `👤 Name: ${name}`,
    `📡 Channel: ${channelId}`,
    ``,
    `To approve:`,
    approveCmd,
    ``,
    `💡 To use a different group, replace "restricted" with:`,
    `trusted | partner | friends | family | work`,
    ``,
    `To change the group later: run the same command with the desired group.`,
    ``,
    `To remove:`,
    removeCmd,
  ].join("\n");

  try {
    const response = await fetch("http://127.0.0.1:18789/tools/invoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${GATEWAY_TOKEN}`,
      },
      body: JSON.stringify({
        tool: "message",
        action: "send",
        args: {
          channel: OPERATOR_CHANNEL,
          target: OPERATOR_TARGET,
          message: notification,
        },
        sessionKey: "main",
      }),
    });
    const result = await response.text();
    console.log("[access-request] Resposta:", response.status, result);
  } catch (err) {
    console.error("[access-request] Falha ao notificar:", err);
  }
};

export default handler;
