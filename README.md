# 🛡️ Inquisitor — Discord ↔ Minecraft Server Control Bot

**Inquisitor** is a Discord bot designed to securely manage and monitor a Minecraft server using RCON, with a robust, tiered permissions system that can synchronize with Discord roles.
It supports player moderation, whitelist management (Java & Bedrock), server commands, and live server presence updates — all controlled through Discord slash commands.

This project is designed for **self-hosted Minecraft servers**, including Docker-based setups.

---

## 📌 Core Features

* 🔐 **Tiered Permission System**

  * Guest → Member → Mod → Owner
  * Inherited permissions with per-user overrides
  * Persistent JSON-backed permissions

* 🔄 **Bidirectional Discord Role Sync**

  * Discord roles are authoritative on startup and reload
  * Inquisitor role changes update Discord immediately
  * Bot accounts are safely ignored

* 🎮 **Minecraft RCON Integration**

  * Kick, ban, unban
  * Java whitelist / unwhitelist
  * Bedrock whitelist via `fwhitelist`
  * Server command execution

* 👤 **Minecraft IGN Registration**

  * Users can self-register their IGN
  * Owners can register multiple IGNs per Discord user
  * UUIDs resolved via Minecraft `usercache.json`
  * Duplicate IGN protection across Discord users

* 🟢 **Live Server Presence**

  * Discord bot status shows online player count
  * Automatically updates via RCON polling

* 🧪 **Diagnostic Tooling**

  * Discord role/member dump script
  * RCON connectivity test script

---

## 📂 Repository Structure

```
inquisitor/
├── inquisitor_13.1.py            # Main bot entrypoint
├── inquisitor_perms_2.py         # Permission system logic
├── inquisitor_perms.json         # Persistent permissions database
├── mc_rcon.py                    # RCON wrapper used by Inquisitor
├── rcon_config.py                # RCON host/port/password
├── inquisitor_token.py           # Discord token + IDs (NOT committed)
├── discord_dump_roles_members.py # Discord diagnostic script
├── rcon_test.py                  # RCON diagnostic script
├── logs/                         # Runtime logs
└── README.md
```

---

## 🔧 Requirements

### System

* Linux (recommended)
* Python **3.10+**
* Network access to Minecraft RCON port

### Python Packages

Install inside a virtual environment:

```bash
pip install discord.py
```

---

## 🔑 Configuration Files

### `inquisitor_token.py` (REQUIRED)

```python
INQUISITOR_TOKEN = "YOUR_DISCORD_BOT_TOKEN"
GUILD_ID = 123456789012345678
PREFIX = "!"
```

> ⚠️ **Never commit this file**

---

### `rcon_config.py`

```python
HOST = "127.0.0.1"
PORT = 25575
PASSWORD = "your_rcon_password"
```

---

### Minecraft `usercache.json`

Set this near the top of `inquisitor_13.1.py`:

```python
USERCACHE_PATH = "/path/to/usercache.json"
```

Required for IGN → UUID resolution.

---

## 🔐 Permission System

Permissions are stored in `inquisitor_perms.json`.

### Roles (Inheritance-Based)

| Role   | Inherits From | Description    |
| ------ | ------------- | -------------- |
| Guest  | —             | Default role   |
| Member | Guest         | Trusted player |
| Mod    | Member        | Moderation     |
| Owner  | Mod           | Full control   |

### Default Capabilities

| Permission              | Guest | Member | Mod | Owner |
| ----------------------- | ----- | ------ | --- | ----- |
| weather_clear           | ✅     | ✅      | ✅   | ✅     |
| kick                    | ❌     | ✅      | ✅   | ✅     |
| whitelist / unwhitelist | ❌     | ❌      | ✅   | ✅     |
| ban / unban             | ❌     | ❌      | ❌   | ✅     |
| admin_message           | ❌     | ❌      | ❌   | ✅     |
| bot_message             | ❌     | ❌      | ❌   | ✅     |
| set_role                | ❌     | ❌      | ❌   | ✅     |
| set_permission          | ❌     | ❌      | ❌   | ✅     |
| set_blocker             | ❌     | ❌      | ❌   | ✅     |

Owners are **unbannable and unwhitelistable by default**.

---

## 🔄 Discord Role Synchronization

```python
sync_to_discord_roles = True
```

```python
INQ_ROLE_TO_DISCORD_ROLE = {
    "guest": "Guest",
    "member": "Member",
    "mod": "Mod",
    "owner": "Admin",
}
```

**Behavior**

* Startup & reload: Discord → Inquisitor
* Live commands: Inquisitor → Discord
* Overrides are preserved
* Bot accounts ignored

---

## 🎮 Minecraft IGN Registration

### User Commands

* `/register_my_ign`
* `/unregister_my_ign`

### Owner Commands

* `/register_player_ign <discord_user> <IGN>`
* `/unregister_player_ign <discord_user>`

---

## 🧾 Supported Slash Commands

weather_clear, kick, ban, unban, whitelist, unwhitelist,
bedrock_whitelist, bedrock_unwhitelist, bot_command, bot_message,
admin_message, set_role, set_permission, set_blocker,
register_my_ign, register_player_ign, unregister_my_ign, unregister_player_ign

---

## 🟢 Presence System

Bot status automatically reflects player count using RCON `list`.

---

## 🧪 Diagnostics

```bash
python3 rcon_test.py
python3 discord_dump_roles_members.py --verbose
```

---

## ▶️ Running Inquisitor

```bash
python3 inquisitor_13.1.py
```

---

## 🔐 Security Notes

* Never commit secrets
* Restrict RCON exposure
* Bot role must be above managed roles

---

## ✨ Project Philosophy

Explicit over magical. Safe over clever. Auditable and deterministic.
# 🛡️ Inquisitor — Discord ↔ Minecraft Server Control Bot

**Inquisitor** is a Discord bot designed to securely manage and monitor a Minecraft server using RCON, with a robust, tiered permissions system that can synchronize with Discord roles.
It supports player moderation, whitelist management (Java & Bedrock), server commands, and live server presence updates — all controlled through Discord slash commands.

This project is designed for **self-hosted Minecraft servers**, including Docker-based setups.

---

## 📌 Core Features

* 🔐 **Tiered Permission System**

  * Guest → Member → Mod → Owner
  * Inherited permissions with per-user overrides
  * Persistent JSON-backed permissions

* 🔄 **Bidirectional Discord Role Sync**

  * Discord roles are authoritative on startup and reload
  * Inquisitor role changes update Discord immediately
  * Bot accounts are safely ignored

* 🎮 **Minecraft RCON Integration**

  * Kick, ban, unban
  * Java whitelist / unwhitelist
  * Bedrock whitelist via `fwhitelist`
  * Server command execution

* 👤 **Minecraft IGN Registration**

  * Users can self-register their IGN
  * Owners can register multiple IGNs per Discord user
  * UUIDs resolved via Minecraft `usercache.json`
  * Duplicate IGN protection across Discord users

* 🟢 **Live Server Presence**

  * Discord bot status shows online player count
  * Automatically updates via RCON polling

* 🧪 **Diagnostic Tooling**

  * Discord role/member dump script
  * RCON connectivity test script

---

## 📂 Repository Structure

```
inquisitor/
├── inquisitor_13.1.py            # Main bot entrypoint
├── inquisitor_perms_2.py         # Permission system logic
├── inquisitor_perms.json         # Persistent permissions database
├── mc_rcon.py                    # RCON wrapper used by Inquisitor
├── rcon_config.py                # RCON host/port/password
├── inquisitor_token.py           # Discord token + IDs (NOT committed)
├── discord_dump_roles_members.py # Discord diagnostic script
├── rcon_test.py                  # RCON diagnostic script
├── logs/                         # Runtime logs
└── README.md
```

---

## 🔧 Requirements

### System

* Linux (recommended)
* Python **3.10+**
* Network access to Minecraft RCON port

### Python Packages

Install inside a virtual environment:

```bash
pip install discord.py
```

---

## 🔑 Configuration Files

### `inquisitor_token.py` (REQUIRED)

```python
INQUISITOR_TOKEN = "YOUR_DISCORD_BOT_TOKEN"
GUILD_ID = 123456789012345678
PREFIX = "!"
```

> ⚠️ **Never commit this file**

---

### `rcon_config.py`

```python
HOST = "127.0.0.1"
PORT = 41968
PASSWORD = "your_rcon_password"
```

---

### Minecraft `usercache.json`

Set this near the top of `inquisitor_13.1.py`:

```python
USERCACHE_PATH = "/path/to/usercache.json"
```

# 🛡️ Inquisitor — Discord ↔ Minecraft Server Control Bot

**Inquisitor** is a Discord bot designed to securely manage and monitor a Minecraft server using RCON, with a robust, tiered permissions system that can synchronize with Discord roles.
It supports player moderation, whitelist management (Java & Bedrock), server commands, and live server presence updates — all controlled through Discord slash commands.

This project is designed for **self-hosted Minecraft servers**, including Docker-based setups.

---

## 📌 Core Features

* 🔐 **Tiered Permission System**

  * Guest → Member → Mod → Owner
  * Inherited permissions with per-user overrides
  * Persistent JSON-backed permissions

* 🔄 **Bidirectional Discord Role Sync**

  * Discord roles are authoritative on startup and reload
  * Inquisitor role changes update Discord immediately
  * Bot accounts are safely ignored

* 🎮 **Minecraft RCON Integration**

  * Kick, ban, unban
  * Java whitelist / unwhitelist
  * Bedrock whitelist via `fwhitelist`
  * Server command execution

* 👤 **Minecraft IGN Registration**

  * Users can self-register their IGN
  * Owners can register multiple IGNs per Discord user
  * UUIDs resolved via Minecraft `usercache.json`
  * Duplicate IGN protection across Discord users

* 🟢 **Live Server Presence**

  * Discord bot status shows online player count
  * Automatically updates via RCON polling

* 🧪 **Diagnostic Tooling**

  * Discord role/member dump script
  * RCON connectivity test script

---

## 📂 Repository Structure

```
inquisitor/
├── inquisitor_13.1.py            # Main bot entrypoint
├── inquisitor_perms_2.py         # Permission system logic
├── inquisitor_perms.json         # Persistent permissions database
├── mc_rcon.py                    # RCON wrapper used by Inquisitor
├── rcon_config.py                # RCON host/port/password
├── inquisitor_token.py           # Discord token + IDs (NOT committed)
├── discord_dump_roles_members.py # Discord diagnostic script
├── rcon_test.py                  # RCON diagnostic script
├── logs/                         # Runtime logs
└── README.md
```

---

## 🔧 Requirements

### System

* Linux (recommended)
* Python **3.10+**
* Network access to Minecraft RCON port

### Python Packages

Install inside a virtual environment:

```bash
pip install discord.py
```

---

## 🔑 Configuration Files

### `inquisitor_token.py` (REQUIRED)

```python
INQUISITOR_TOKEN = "YOUR_DISCORD_BOT_TOKEN"
GUILD_ID = 123456789012345678
PREFIX = "!"
```

> ⚠️ **Never commit this file**

---

### `rcon_config.py`

```python
HOST = "127.0.0.1"
PORT = 41968
PASSWORD = "your_rcon_password"
```

---

### Minecraft `usercache.json`

Set this near the top of `inquisitor_13.1.py`:

```python
USERCACHE_PATH = "/path/to/usercache.json"
```

Required for IGN → UUID resolution.

---

## 🔐 Permission System

Permissions are stored in `inquisitor_perms.json`.

### Roles (Inheritance-Based)

| Role   | Inherits From | Description    |
| ------ | ------------- | -------------- |
| Guest  | —             | Default role   |
| Member | Guest         | Trusted player |
| Mod    | Member        | Moderation     |
| Owner  | Mod           | Full control   |

### Default Capabilities

| Permission              | Guest | Member | Mod | Owner |
| ----------------------- | ----- | ------ | --- | ----- |
| weather_clear           | ✅     | ✅      | ✅   | ✅     |
| kick                    | ❌     | ✅      | ✅   | ✅     |
| whitelist / unwhitelist | ❌     | ❌      | ✅   | ✅     |
| ban / unban             | ❌     | ❌      | ❌   | ✅     |
| admin_message           | ❌     | ❌      | ❌   | ✅     |
| bot_message             | ❌     | ❌      | ❌   | ✅     |
| set_role                | ❌     | ❌      | ❌   | ✅     |
| set_permission          | ❌     | ❌      | ❌   | ✅     |
| set_blocker             | ❌     | ❌      | ❌   | ✅     |

Owners are **unbannable and unwhitelistable by default**.

---

## 🔄 Discord Role Synchronization

```python
sync_to_discord_roles = True
```

```python
INQ_ROLE_TO_DISCORD_ROLE = {
    "guest": "Guest",
    "member": "Member",
    "mod": "Mod",
    "owner": "Admin",
}
```

**Behavior**

* Startup & reload: Discord → Inquisitor
* Live commands: Inquisitor → Discord
* Overrides are preserved
* Bot accounts ignored

---

## 🎮 Minecraft IGN Registration

### User Commands

* `/register_my_ign`
* `/unregister_my_ign`

### Owner Commands

* `/register_player_ign <discord_user> <IGN>`
* `/unregister_player_ign <discord_user>`

---

## 🧾 Supported Slash Commands

weather_clear, kick, ban, unban, whitelist, unwhitelist,
bedrock_whitelist, bedrock_unwhitelist, bot_command, bot_message,
admin_message, set_role, set_permission, set_blocker,
register_my_ign, register_player_ign, unregister_my_ign, unregister_player_ign

---

## 🟢 Presence System

Bot status automatically reflects player count using RCON `list`.

---

## 🧪 Diagnostics

```bash
python3 rcon_test.py
python3 discord_dump_roles_members.py --verbose
```

---

## ▶️ Running Inquisitor

```bash
python3 inquisitor_13.1.py
```

---

## 🔐 Security Notes

* Never commit secrets
* Restrict RCON exposure
* Bot role must be above managed roles

---

## ✨ Project Philosophy

Explicit over magical. Safe over clever. Auditable and deterministic.
Required for IGN → UUID resolution.

---

## 🔐 Permission System

Permissions are stored in `inquisitor_perms.json`.

### Roles (Inheritance-Based)

| Role   | Inherits From | Description    |
| ------ | ------------- | -------------- |
| Guest  | —             | Default role   |
| Member | Guest         | Trusted player |
| Mod    | Member        | Moderation     |
| Owner  | Mod           | Full control   |

### Default Capabilities

| Permission              | Guest | Member | Mod | Owner |
| ----------------------- | ----- | ------ | --- | ----- |
| weather_clear           | ✅     | ✅      | ✅   | ✅     |
| kick                    | ❌     | ✅      | ✅   | ✅     |
| whitelist / unwhitelist | ❌     | ❌      | ✅   | ✅     |
| ban / unban             | ❌     | ❌      | ❌   | ✅     |
| admin_message           | ❌     | ❌      | ❌   | ✅     |
| bot_message             | ❌     | ❌      | ❌   | ✅     |
| set_role                | ❌     | ❌      | ❌   | ✅     |
| set_permission          | ❌     | ❌      | ❌   | ✅     |
| set_blocker             | ❌     | ❌      | ❌   | ✅     |

Owners are **unbannable and unwhitelistable by default**.

---

## 🔄 Discord Role Synchronization

```python
sync_to_discord_roles = True
```

```python
INQ_ROLE_TO_DISCORD_ROLE = {
    "guest": "Guest",
    "member": "Member",
    "mod": "Mod",
    "owner": "Admin",
}
```

**Behavior**

* Startup & reload: Discord → Inquisitor
* Live commands: Inquisitor → Discord
* Overrides are preserved
* Bot accounts ignored

---

## 🎮 Minecraft IGN Registration

### User Commands

* `/register_my_ign`
* `/unregister_my_ign`

### Owner Commands

* `/register_player_ign <discord_user> <IGN>`
* `/unregister_player_ign <discord_user>`

---

## 🧾 Supported Slash Commands

weather_clear, kick, ban, unban, whitelist, unwhitelist,
bedrock_whitelist, bedrock_unwhitelist, bot_command, bot_message,
admin_message, set_role, set_permission, set_blocker,
register_my_ign, register_player_ign, unregister_my_ign, unregister_player_ign

---

## 🟢 Presence System

Bot status automatically reflects player count using RCON `list`.

---

## 🧪 Diagnostics

```bash
python3 rcon_test.py
python3 discord_dump_roles_members.py --verbose
```

---

## ▶️ Running Inquisitor

```bash
python3 inquisitor_13.1.py
```

---

## 🔐 Security Notes

* Never commit secrets
* Restrict RCON exposure
* Bot role must be above managed roles

---

## ✨ Project Philosophy

Explicit over magical. Safe over clever. Auditable and deterministic.
