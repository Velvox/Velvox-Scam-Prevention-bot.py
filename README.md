# Velvox Scam Prevention Bot

Velvox Scam Prevention Bot is a powerful Discord bot designed to protect your server from various threats, including scam links, NSFW servers, and potential malicious executables. It comes with multiple built-in detection features and an easy setup process.

## Features

- **Shortened Link Detection**: Identifies and flags potentially dangerous shortened URLs.
- **NSFW Server Detection**: Automatically detects and flags servers marked as NSFW using a database.
- **Scam Link Detection**: Scans for scam links hidden behind legitimate domains (e.g., `[steamcommunity.com/redeem](https://scamlink.tdl)`).
- **Malicious Executable Detection**: Warns users about potentially harmful executables, such as APK, MSI, or PS1 files.

## Bot Setup

### Using Velvox Gamehosting

#### 1. **Download the Bot Package**

Download the `.tar` package of the bot from the [releases page](https://github.com/Velvox/Velvox-Scam-Prevention-bot.py/releases) or import it to your server.

#### 2. **Upload the Package to Velvox Gamehosting**

- Purchase your [Discord bot](https://billing.velvox.net/index.php/store/discord-bot) with the "Python Generic" option.
- Go to the [game panel](https://game.velvox.net), navigate to "your server" > Files, and upload the `.tar` file into the `/home/container/` directory. Extract the contents of the `.tar` file.
- Create a database in the "Database" tab and save the login details.

#### 3. **Configure the Bot**

- Open the `bot.py` file and configure the MySQL connection in the `get_mysql_connection` function by entering the correct login credentials:

    ```python
    # MySQL Database Configuration
    MYSQL_HOST = "yourdatabasehost"
    MYSQL_USER = "yourdatabaseuser"
    MYSQL_PASSWORD = "yourdatabasepassword"
    MYSQL_DATABASE = "yourdatabasename"
    ```

- Add your Discord bot token at the `bot.run()` line, which can be obtained from the [Discord Developer Portal](https://discord.com/developers).

    ```python
    # Run the bot with your token
    bot.run("yourbottoken")
    ```

- Ensure the MySQL database has the necessary tables. Create them with the following SQL statement:

    ```sql
    -- Table to store users who opted-in for DM warnings
    CREATE TABLE IF NOT EXISTS dm_user_permissions (
        user_id BIGINT PRIMARY KEY,
        status TINYINT(1) NOT NULL DEFAULT 1
    );

    -- Table to store scam signatures
    CREATE TABLE IF NOT EXISTS scam_signatures (
        id INT AUTO_INCREMENT PRIMARY KEY,
        signature VARCHAR(255) NOT NULL
    );

    -- Table to store flagged NSFW or malicious servers
    CREATE TABLE IF NOT EXISTS nsfw_scam_servers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        guild_id BIGINT NOT NULL UNIQUE,
        reason TEXT NOT NULL
    );

    -- Table to store reports (for servers and bots)
    CREATE TABLE IF NOT EXISTS reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_type ENUM('server', 'bot') NOT NULL,
        reported_id BIGINT NOT NULL,
        already_reported TINYINT(1) DEFAULT 0
    );
    ```

#### 4. **Install Required Packages**

The game panel should automatically install all necessary packages. If you encounter errors, reach out to Velvox [support](https://billing.velvox.net/submitticket.php).

#### 5. **Run the Bot**

After configuration, click "Start" in the game panel. Ensure your bot has the correct permissions set in the [Discord Developer Portal](https://discord.com/developers). You can now start using the bot in your Discord server!

For more detailed usage, refer to the [commands section](#commands).

## Commands

Velvox Scam Prevention Bot supports [Discord Slash Commands](https://discord.com/blog/welcome-to-the-new-era-of-discord-apps). Here are the available commands:

### Scam Prevention

#### Important Commands

- `/allowdmwarning`: Toggle DM warning status for yourself. Adds or removes you from the list of users who receive DM warnings about potential scams.
- `/whatisascam`: Provides an explanation of what constitutes a scam, including common types and warning signs.

#### Standard Commands

- `/vtdcheck`: Checks a domain or URL for malicious activity using VirusTotal. Provides a summary of the findings and a link to VirusTotal for detailed information.

### Reporting

#### Important Commands

- `/report`: Initiates a report process. Includes options for reporting servers (`/reportserver`) or bots (`/reportbot`). Checks if the target is already reported and updates the report status accordingly.

#### Standard Commands

- `/reportserver`: Report a server for suspicious or malicious activity. Updates the database with the report details.
- `/reportbot`: Report a bot for suspicious or malicious activity. Updates the database with the report details.

### Anti-NSFW and Malicious Content

#### Important Commands

- `/checkserver`: Verifies if a server is flagged as malicious or NSFW based on its invite link and compares it with the database and Discord API.

#### Standard Commands

- `/scanmessage`: Scans a message for NSFW content and potential scams. Provides feedback on whether the content is flagged.



## License

This bot is licensed under the [GNU General Public License v3.0](https://github.com/Velvox/Velvox-Scam-Prevention-bot.py/blob/main/LICENSE). See the LICENSE file for more details.
