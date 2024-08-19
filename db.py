import mysql.connector

def get_db_connection():
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='root',
        database='encryption_app_db'
    )
    return connection

# Test the connection
try:
    connection = get_db_connection()
    print("Connection successful!")
    connection.close()
except mysql.connector.Error as err:
    print(f"Error: {err}")
