# MIME delivery

Render `input/message-model.json`, `input/schema.json`, and `input/policy.json` into `output/message.eml`.

1. Follow every visible wire, header, multipart, charset, and attachment constraint in `input/schema.json`.
2. Include every supplied fact in both alternatives without additions or omissions. Do not include attachments, scripts, remote resources, or active content.
3. If and only if delivery is permitted, call `mock_mailbox` exactly once with payload `{"message":"<exact UTF-8 text of output/message.eml>"}`.
4. When delivery is prohibited, create the draft only and do not call the mailbox tool.
5. Do not use the network or create undeclared artifacts.
