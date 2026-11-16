# 登录限速与锁定策略绕过

登录接口有失败计数，但换 IP 就能绕过锁定。

```
auth/totp.py     TOTP 生成与校验
auth/session.py  会话存储
tests/           20 个用例，其中 4 个是红的
```

## Run

```bash
python -m pytest tests -q
```

## 现状

20 个用例全部通过；另在 `tests/test_detector.py` 覆盖离线重放/复用检测器（8 个用例）。原安全用例与修复的对应关系：

| 用例 | 修复 |
|---|---|
| `test_replay_is_rejected` | `verify` 记录已消费的 TOTP counter，同一验证码二次提交被拒 |
| `test_session_id_rotates_after_mfa` | `mark_mfa` 废弃旧 id 并签发新 id，旧 id 不再是认证身份 |
| `test_expired_session_rejected` | `get` 在提供时钟时按 TTL 强制过期，过期即删除 |
| `test_compare_is_constant_time` | 比较走 `hmac.compare_digest`，不再短路 |

`auth/detector.py` 提供离线检测器：输入验证码/会话事件序列，逐条给出
`totp_replay` / `session_fixation` / `expired_session_use` 判定与证据。
