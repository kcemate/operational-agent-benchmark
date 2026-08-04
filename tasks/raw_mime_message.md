# Raw MIME message

Read `input/message.json` and write a defect-free `submission/message.eml`.

Requirements:
- exact `From`, `To`, `Subject`, and `Date` values from the input;
- `MIME-Version: 1.0`;
- `multipart/alternative` with exactly one UTF-8 `text/plain` part and one UTF-8 `text/html` part;
- both alternatives must include the exact `summary`, `metric`, and `next_step` values from the input;
- no attachments, malformed addresses, duplicate singleton headers, missing boundary terminator, or parser defects.

Do not invent facts.
