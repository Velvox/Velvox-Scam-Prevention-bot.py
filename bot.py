import discord
from discord.ext import commands, tasks
import pymysql
import config
import re
import aiohttp
import itertools
import hashlib
from urllib.parse import urlparse

# Create bot instance with intents
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix='!', intents=intents)

db_config = config.db_config

# List of bot activities
activities = itertools.cycle([
    discord.Activity(type=discord.ActivityType.watching, name="for URL shortners..."),
    discord.Activity(type=discord.ActivityType.competing, name="anti phishing"),
    discord.Activity(type=discord.ActivityType.watching, name="for hacked accounts"),
    discord.Activity(type=discord.ActivityType.playing, name="with VirusTotal data"),
    discord.Activity(type=discord.ActivityType.watching, name="Tria.ge analasys"),
    discord.Activity(type=discord.ActivityType.competing, name="SHA256 generation"),
    discord.Activity(type=discord.ActivityType.watching, name="URLs for threats"),
    discord.Activity(type=discord.ActivityType.watching, name="phishing attempts unfold"),
    discord.Activity(type=discord.ActivityType.watching, name="malicious invite links"),
    discord.Activity(type=discord.ActivityType.playing, name="with API data")
])


# Function to load DM user permissions from the database
def load_dmuser_permissions():
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        cursor.execute("SELECT user_id FROM dm_user_permissions WHERE status = 1")
        users = cursor.fetchall()
        connection.close()
        return [user['user_id'] for user in users]

# Function to load scam signatures from the MySQL database
def load_signatures():
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        cursor.execute("SELECT signature FROM scam_signatures")
        signatures = cursor.fetchall()
        connection.close()
        return [s['signature'] for s in signatures]

# Function to check if the message contains a scam signature
def check_for_scam(message_content, signatures):
    for signature in signatures:
        if re.search(signature, message_content, re.IGNORECASE):
            return True
    return False

# Function to extract the domain
def extract_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    return domain.split('.')[-2] + '.' + domain.split('.')[-1]

# Function to check if the URL is shortened
def is_shortened_url(url):
    domain = extract_domain(url)
    return domain in SHORTENERS

# Function to expand shortened URLs
async def expand_url(shortened_url):
    """Function to expand a shortened URL to its full form."""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(shortened_url, allow_redirects=True) as response:  # Use GET to follow redirects
                return str(response.url)  # Ensure it's always a string
        except Exception as e:
            print(f"Error expanding shortened URL: {e}")
            return str(shortened_url)  # Fallback to original if an error occurs

# Function to check if the URL is shortened
def is_shortened_url(url):
    domain = extract_domain(url)
    return domain in SHORTENERS

# Function to check if a server is flagged as NSFW/malicious
async def check_server_status(invite_code):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f'https://discord.com/api/v10/invites/{invite_code}') as response:
                if response.status == 200:
                    data = await response.json()
                    guild_id = data.get('guild', {}).get('id')
                    
                    if guild_id:
                        connection = pymysql.connect(**db_config)
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT guild_id FROM nsfw_scam_servers WHERE guild_id = %s", (guild_id,))
                            result = cursor.fetchone()
                            connection.close()
                            if result:
                                return True
                return False
        except Exception as e:
            print(f"Error checking server status: {e}")
            return False
        
# Function to download file and calculate hash (in memory)
async def download_file_and_hash(attachment_url):
    async with aiohttp.ClientSession() as session:
        async with session.get(attachment_url) as resp:
            if resp.status == 200:
                file_data = await resp.read()  # Keep file data in memory
                sha256_hash = hashlib.sha256(file_data).hexdigest()  # Hash the in-memory file
                return sha256_hash
    return None
        
# Function to change bot activity every 5 seconds
@tasks.loop(seconds=5)
async def change_activity():
    current_activity = next(activities)
    await bot.change_presence(activity=current_activity)
 
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    change_activity.start()  # Start the loop when the bot is ready
    # Sync slash commands with Discord
    await bot.tree.sync()
    print('Slash commands synchronized with Discord.')

# List of known URL shorteners
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "shorturl.com",
    "is.gd", "buff.ly", "rebrand.ly", "adf.ly", "shorte.st", "qr.net",
    "bl.ink", "t2m.io", "clicky.me", "v.gd", "s.id", "yourls.org",
    "snip.ly", "cutt.ly", "lnkd.in", "linktr.ee", "short.ie", "amzn.to",
    "lil.link", "clk.im", "plink.io", "link.sh", "shrtco.de", "go2l.ink",
    "cli.re", "short.cm", "tr.im", "mcaf.ee", "j.mp", "linkz.ai",
    "short.link", "fast.io", "shorturl.at", "y2u.be", "linkd.in", "u.to"
]

# List of suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
    ".bat", ".vbs", ".ps1", ".cmd", ".js", ".scr", ".pl", ".py",
    ".sh", ".command", ".applescript", ".cgi", ".jar", ".rb",
    ".com", ".iso", ".rar", ".tar", ".zip", ".7z"
]

# Set max file upload size for the /check file command
CHECK_FILE_MAX_FILE_SIZE = 500 * 1024 * 1024  

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return  # Ignore messages sent by the bot itself

    # Load necessary data
    signatures = load_signatures()
    authorized_user_ids = load_dmuser_permissions()
    safe_message = True  # Assume message is safe initially

    # Check for scams
    if check_for_scam(message.content, signatures):
        scam_info_embed = discord.Embed(
            title="❗Possible Scam Detected❗",
            description="We've detected that one of the messages might resemble a common scam. Please review the following details:",
            color=discord.Color.red()
        )
        scam_info_embed.add_field(
            name="What are scams?",
            value="Scams often attempt to trick users into sharing login, banking, or other personal information. Be cautious of suspicious links and requests."
        )
        scam_info_embed.add_field(
            name="Common Scam Types",
            value='1. Phishing\n2. Fake Giveaways\n3. "Sorry I reported you" (Often used to phish for login info)\n4. Discord staff impersonation scams'
        )
        scam_info_embed.add_field(
            name="Have you been scammed or phished?",
            value="Run the command /igotscammed",
            inline=False
        )
        scam_info_embed.add_field(
            name="Message Link",
            value=f"[Click here to view the message](https://discord.com/channels/{message.guild.id}/{message.channel.id}/{message.id})",
            inline=False
        )
        scam_info_embed.set_footer(text="Built, hosted, and maintained by Velvox. This is an open-source project.")

        try:
            await message.channel.send(embed=scam_info_embed)
        except discord.errors.Forbidden:
            print("Couldn't send message in the channel, the bot might not have the right permissions.")

        # Send DM only to authorized users
        for member in message.guild.members:
            if member.bot:
                continue  # Skip bots

            if member.id in authorized_user_ids:
                try:
                    await member.send(embed=scam_info_embed)
                except discord.errors.Forbidden:
                    print(f"Couldn't DM {member.name}, they might have DMs disabled.")
                except discord.errors.HTTPException as e:
                    print(f"HTTPException while DMing {member.name}: {e}")

    # Check for shortened links
    urls = re.findall(r'https?://\S+', message.content)
    for url in urls:
        if is_shortened_url(url):
            # Expand the shortened URL
            expanded_url = await expand_url(url)
            domain = extract_domain(expanded_url)

            embed = discord.Embed(
                title="⚠️ Shortened Link Detected",
                description="We've detected that a shortened link was posted. Be cautious as these links can hide malicious content.",
                color=discord.Color.orange()
            )
            embed.add_field(
                name="Shortened Link",
                value=f"**`{url}`**",
                inline=False
            )
            embed.add_field(
                name="Expanded Link",
                value=f"**`{expanded_url}`**",
                inline=False
            )

            if domain:
                embed.add_field(
                    name="<:vtlogo:1281911851793514536> Check the Domain/URL with VirusTotal",
                    value=f"[Click here to check **{domain}** on VirusTotal](https://www.virustotal.com/gui/domain/{domain})",
                    inline=False
                )

            embed.set_footer(text="Built, hosted, and maintained by Velvox. This is an open-source project.")

            try:
                await message.channel.send(embed=embed)
            except discord.errors.Forbidden:
                print("Couldn't send message in the channel, the bot might not have the right permissions.")
            safe_message = False  # Mark message as unsafe for deletion
            break

    # Check for suspicious file attachments
    for attachment in message.attachments:
        file_name = attachment.filename
        if any(file_name.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            embed = discord.Embed(
                title="⚠️ Suspicious File Detected",
                description="A potentially dangerous file has been detected. Please review the details below.",
                color=discord.Color.orange()
            )
            embed.add_field(
                name="File Name",
                value=f"**{file_name}**",
                inline=False
            )
            embed.add_field(
                name="File Size",
                value=f"{attachment.size / 1024:.2f} KB",
                inline=False
            )
            embed.add_field(
                name="Don't download random files!",
                value="Ensure you know and trust the person that sends this file. Don't download random or strange programs from Discord, and **NEVER** turn off your anti-virus/malware protection!",
                inline=False
            )
            embed.set_footer(text="Built, hosted, and maintained by Velvox. This is an open-source project.")

            # Download the file and calculate its hash (in-memory)
            file_hash = await download_file_and_hash(attachment.url)
            if file_hash:
                virus_total_url = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
                embed.add_field(
                    name="Check if the file is malicious with VirusTotal",
                    value=f"[Check **{file_name}** on VirusTotal]({virus_total_url})",
                    inline=False
                )
                tria_ge_url = f"https://tria.ge/s?q={file_hash}"
                embed.add_field(
                    name="Analyze the file further with Triage",
                    value=f"[Check **{file_name}** on Tria.ge]({tria_ge_url})",
                    inline=False
                )
                embed.add_field(
                    name="SHA256 hash of file",
                    value=f"`{file_hash}`",
                    inline=False
                )
                

            # Send the embed
            try:
                await message.channel.send(embed=embed)
            except discord.errors.Forbidden:
                print("Couldn't send message in the channel, the bot might not have the right permissions.")

            safe_message = False  # Mark message as unsafe for deletion
            break

    # Check for malicious or NSFW server
    # Regex for URLs with /invite/
    invite_urls_with_invite = re.findall(
        r'https://discord(?:\.com|\.gg|\.app\.com)/invite/([a-zA-Z0-9_-]+)',
        message.content
    )

    # Regex for URLs without /invite/ (direct short links)
    invite_urls_without_invite = re.findall(
        r'https://discord(?:\.com|\.gg|\.app\.com)/([a-zA-Z0-9_-]+)',
        message.content
    )
    
    # Regex for URL's with 
    invite_url_discord_embedded = re.findall(
    	r'(discord\.gg)/([a-zA-Z0-9_-]+)',
        message.content
    )

    # Combine both results into a single list
    invite_codes = invite_urls_with_invite + invite_urls_without_invite + [code[1] for code in invite_url_discord_embedded]
    
    for invite_code in invite_codes:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"https://discord.com/api/v10/invites/{invite_code}") as response:
                    if response.status == 200:
                        invite_data = await response.json()
                        guild_id = invite_data.get("guild", {}).get("id")

                        if guild_id:
                            # Check against database
                            connection = pymysql.connect(**db_config)
                            with connection.cursor() as cursor:
                                cursor.execute("SELECT reason, guild_id FROM nsfw_scam_servers WHERE guild_id = %s", (guild_id,))
                                result = cursor.fetchone()
                                if result:
                                    reason = result.get("reason", "No description available.")
                                    guild_id = result.get("guild_id", "Unknown server ID")
                                    
                                    await message.channel.send(
                                        embed=discord.Embed(
                                            title="❗Malicious server link detected!❗",
                                            description="This server join link has been flagged as potentially malicious based on our records and the Discord API check. Please exercise caution.\n\nThese servers are often used to harvest user credentials or other data with malicious intent.",
                                            color=discord.Color.red()
                                        ).add_field(
                                            name="Description",
                                            value=reason,
                                            inline=False
                                        ).add_field(
                                            name="Server ID",
                                            value=guild_id,
                                            inline=False
                                         ).add_field(
                                            name="Report false hit",
                                            value="If this embed is placed on the wrong invite URL report it to us! [Report it in a Github issue](https://github.com/Velvox/Velvox-Scam-Prevention-bot.py/issues/new)",
                                            inline=False
                                        ).set_footer(text="Built, hosted, and maintained by Velvox. This is an open-source project.")
                                    )
                                    safe_message = False  # Mark message as unsafe for deletion
            except Exception as e:
                print(f"Error checking invite link: {e}")

    # If the message is flagged as unsafe, delete it
    if not safe_message:
        try:
            await message.delete()
            print(f"Deleted message from {message.author} in {message.channel}.")
        except discord.errors.Forbidden:
            print("Couldn't delete the message, the bot might not have the right permissions.")

    # Ensure bot continues processing commands even if deletion fails
    await bot.process_commands(message)

# /allowdmwarning command
@bot.tree.command(name="allowdmwarning", description="Toggle DM warning status for yourself")
async def allowdmwarning(interaction: discord.Interaction):
    user_id = interaction.user.id
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        # Check if the user is already in the database with status 1
        cursor.execute("SELECT status FROM dm_user_permissions WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        
        if result and result['status'] == 1:
            # User is already in the database with status 1, so remove them
            cursor.execute("DELETE FROM dm_user_permissions WHERE user_id = %s", (user_id,))
            await interaction.response.send_message(embed=discord.Embed(
                title="Removed from DM list",
                description="You have been removed from the DM warning list.",
                color=discord.Color.red()
                ).set_footer(text="Build, hosted and maintained by Velvox. This is an opensource project."),
                ephemeral=True
    )
        else:
            # Add or update user with status 1
            cursor.execute("INSERT INTO dm_user_permissions (user_id, status) VALUES (%s, 1) ON DUPLICATE KEY UPDATE status = 1", (user_id,))
            await interaction.response.send_message(
                embed=discord.Embed(
                    title="Added to DM list",
                    description="You have been added to the DM warning list.",
                    color=discord.Color.green()
                ).set_footer(text="Build, hosted and maintained by Velvox. This is an opensource project."),
                ephemeral=True
    )
            connection.commit()
            connection.close()

# /whatisascam command
@bot.tree.command(name="whatisascam", description="Explains what a scam is")
async def whatisascam(interaction: discord.Interaction):
    scam_info_embed = discord.Embed(
        title="So what is a scam?",
        description="A scam is an attempt to trick people into giving away their login or personal information or even money. Scammers often use deception and manipulation to exploit individuals. Here are some common types of scams:",
        color=discord.Color.blue()
    )
    scam_info_embed.add_field(
        name="Common Scam Types",
        value='1. Phishing\n2. Fake Giveaways \n3. "Sorry i reported you"(Often used to phish for login info)\n4. Discord staff impersonation Scams',
        inline=False
    )
    scam_info_embed.add_field(
        name="How to Protect Yourself",
        value="1. Be cautious of unsolicited messages.\n2. Never send personal or login information on Discord, or to anyone you avent seen in person.\n3. Avoid clicking on suspicious links.\n4. Report any suspicious activity to the appropriate authorities.",
        inline=False
    )
    scam_info_embed.add_field(
        name="I have bin scammed",
        value="Did you download a strange file? Or logged in on a website that looks real? run the command `/igotscammed` to get info and sources to get your account back an protect you in the future.",
        inline=True
    )
    scam_info_embed.set_footer(text="Build, hosted and maintained by Velvox. This is an opensource project.")
    
    await interaction.response.send_message(embed=scam_info_embed, ephemeral=True)
    

# /igotscammed command
@bot.tree.command(name="igotscammed", description="Explains what a scam is")
async def igotscammed(interaction: discord.Interaction):
    igotscammed_embed = discord.Embed(
        title="So you got scammed? Here is what to do!",
        description="We got a short description about what you should and can do when you got phished or scammed on Discord.",
        color=discord.Color.blue()
    )
    igotscammed_embed.add_field(
        name="Report to Discord & Block",
        value="Step 1 will always be to report the user, message and or server to Discord and block the user('s)",
        inline=False
    )
    igotscammed_embed.add_field(
        name="Account recovery",
        value="Did the scammer trick you in changing or filling in any account credentials? You account may now be comprimised! Change your password ASAP and consider enabling 2FA/MFA(Second Factor Authentication/Multi Factor Authenticaton).\n\nYou also may want to contact support of the platform:",
        inline=False
    )
    igotscammed_embed.add_field(
        name="Get support",
        value="Official Discord support: https://support.discord.com/hc/en-us/requests/new?ticket_form_id=4574398270487 \nOffical Steam support: https://help.steampowered.com/wizard/HelpWithAccountStolen.",
        inline=True
    )
    igotscammed_embed.add_field(
        name='Good to take a look!',
        value='Some other things to consider is to apply a credit freeze to accociated payment providers (e.g. you bought Nitro with your creditcard). You should report any fraudulent card activity to your bank and to the corresponding platform.',
        inline=False
    )
    igotscammed_embed.set_footer(text="Build, hosted and maintained by Velvox. This is an opensource project.")
    
    await interaction.response.send_message(embed=igotscammed_embed, ephemeral=True)

@bot.tree.command(name="vtdcheck", description="Check a domain using VirusTotal")
async def vtdcheck(interaction: discord.Interaction, domain: str):
    # Construct the VirusTotal link
    vt_link = f"https://www.virustotal.com/gui/domain/{domain}"

    # Create an embed
    embed = discord.Embed(
        title="VirusTotal Domain Check",
        description=f"[Click here to check {domain} on VirusTotal]({vt_link})",
        color=discord.Color.blue()
    )
    embed.set_footer(text="Use this link to analyze the domain for any threats.")

    # Send the embed
    await interaction.response.send_message(embed=embed)


# /reporthelp command
@bot.tree.command(name="reporthelp", description="Report commands and help.")
async def reporthelp(interaction: discord.Interaction):
    help_embed = discord.Embed(
        title="Report Command Help",
        description="Use the following commands to report a server or bot:",
        color=discord.Color.blue()
    )
    help_embed.add_field(
        name="/reportserver serverid:<server_id> reason:<reason> invitelink:(optional) other:(optional)",
        value="Use this to report a server.",
        inline=False
    )
    help_embed.add_field(
        name="/reportbot botid:<bot_id> reason:<reason> other:(optional)",
        value="Use this to report a bot.",
        inline=False
    )
    help_embed.set_footer(text="Built and maintained by Velvox.")

    await interaction.response.send_message(embed=help_embed, ephemeral=True)

# /reportserver command
@bot.tree.command(name="reportserver", description="Report a Discord server.")
async def report_server(interaction: discord.Interaction, serverid: str, reason: str, invitelink: str = None, other: str = None):
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        # Check if the server is already reported
        cursor.execute("SELECT already_reported FROM reports WHERE server_id = %s", (serverid,))
        result = cursor.fetchone()
        if result and result['already_reported'] == 1:
            await interaction.response.send_message("Server is already reported!", ephemeral=True)
            return

        # Insert the report into the database
        cursor.execute("""
            INSERT INTO reports (server_id, reason, invite_link, other_info, already_reported)
            VALUES (%s, %s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE already_reported = 1
        """, (serverid, reason, invitelink, other))
        connection.commit()

    connection.close()

    await interaction.response.send_message(f"Server {serverid} has been reported.", ephemeral=True)

# /reportbot command
@bot.tree.command(name="reportbot", description="Report a Discord bot.")
async def report_bot(interaction: discord.Interaction, botid: str, reason: str, other: str = None):
    connection = pymysql.connect(**db_config)
    with connection.cursor() as cursor:
        # Check if the bot is already reported
        cursor.execute("SELECT already_reported FROM reports WHERE bot_id = %s", (botid,))
        result = cursor.fetchone()
        if result and result['already_reported'] == 1:
            await interaction.response.send_message("Bot is already reported!", ephemeral=True)
            return

        # Insert the report into the database
        cursor.execute("""
            INSERT INTO reports (bot_id, reason, other_info, already_reported)
            VALUES (%s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE already_reported = 1
        """, (botid, reason, other))
        connection.commit()

    connection.close()

    await interaction.response.send_message(f"Bot {botid} has been reported.", ephemeral=True)

# Define the /checkfile command
@bot.tree.command(name="checkfile", description="Upload a file to check its hash and analyze it! (Max 500MB)")
async def checkfile(interaction: discord.Interaction, file: discord.Attachment):
    # Check file size (limit to 500MB)
    if file.size > 500 * 1024 * 1024:
        await interaction.response.send_message(
            "File is too large. Please upload a file smaller than 500MB.",
            ephemeral=True
        )
        return

    # Download file as bytes (in memory)
    file_bytes = await file.read()

    # Generate SHA256 hash of the file (still in memory)
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # Create URLs for VirusTotal and Tria.ge
    virustotal_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"
    triage_url = f"https://tria.ge/s?q={sha256_hash}"

    # Create embed response
    embed = discord.Embed(
        title="File Check Result",
        description=f"SHA256 hash of the uploaded file: `{sha256_hash}`",
        color=discord.Color.blue()
    )
    embed.add_field(name="VirusTotal Link", value=f"[Check on VirusTotal]({virustotal_url})", inline=False)
    embed.add_field(name="Triage Link", value=f"[Check on Tria.ge]({triage_url})", inline=False)

    # Send embed with results
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="messagedelete", description="Toggle message delete feature for this server")
@commands.has_permissions(administrator=True)
async def messagedelete(interaction: discord.Interaction):
    # Fetch the current value for the guild_id
    guild_id = str(interaction.guild.id)
    connection = pymysql.connect(**db_config)  # Use the dictionary directly here

    try:
        with connection.cursor() as cursor:
            # Check current status
            cursor.execute("SELECT status FROM message_delete WHERE guild_id = %s", (guild_id,))
            result = cursor.fetchone()

            if result:
                current_value = result['status']
                new_value = '0' if current_value == '1' else '1'
                cursor.execute("UPDATE message_delete SET status = %s WHERE guild_id = %s", (new_value, guild_id))
                message = "Message delete feature is now enabled. (You may need to change the bot permissions due to it being very little to enhance enduser privacy)" if new_value == '1' else "Message delete feature is now disabled. (Consider restricting the bot permissions to the default to enhance user privacy)"
            else:
                cursor.execute("INSERT INTO message_delete (guild_id, status) VALUES (%s, '1')", (guild_id,))
                message = "Message delete feature is now enabled. (You may need to change the bot permissions due to it being very little to enhance enduser privacy)"

            connection.commit()
    finally:
        connection.close()

    await interaction.response.send_message(message, ephemeral=True)

# Define the botinfo command
@bot.tree.command(name='botinfo', description='Get information about the bot.')
async def botinfo(interaction: discord.Interaction):
    # Create an embed object
    embed = discord.Embed(
        title="Bot Information",
        description=(
            "Hello! I am the Velvox Scam Prevention Bot (VSPB), I protect users against scams and phishing attempts.\n You can set if you personaly want a DM if a scam is detected by sending `/allowdmwarning` in this channel.\n\n To report a server you can send `/reporthelp` and you will get extra info about reporting a malicouis bot or server.\n\n You can use `/vtdcheck` to check a domain for know malicouis signatures! Or use /checkfile to upload a file and get the hash to check it at VirusTotal or other vendor's!"
        ),
        color=discord.Color.blue()  # You can customize the color
    )
    
    embed.add_field(
        name="<:velvox:1250723798559232101> Hosted at Velvox Gamehosting",
        value="This bot is hosted and maintained by [Velvox](https://velvox.net)"
    )

    # Send the embed message
    await interaction.response.send_message(embed=embed)

# Run the bot
bot.run(config.BOT_TOKEN)
