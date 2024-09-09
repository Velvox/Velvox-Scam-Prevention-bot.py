import pymysql
# Bot configuration
BOT_TOKEN = 'yourbottoken'
# MySQL configuration
MYSQLUSER = 'yourdatabaseuser'
MYSQLPASSOWRD = 'yourdatabasepassword'
MYSQLDATABASE = 'yourdatabasename'
MYSQLHOST = 'yourdatabasehost'
# Static Database config DONT CHANGE!!
db_config = {
    'host': MYSQLHOST,  # Change this to your MySQL host
    'user': MYSQLUSER,  # Your MySQL username
    'password': MYSQLPASSOWRD,  # Your MySQL password
    'database': MYSQLDATABASE,  # Your database name
    'cursorclass': pymysql.cursors.DictCursor
}
