#!/usr/bin/python3
import sys
import sqlite3
from datetime import datetime, timezone

def main():
    db = sqlite3.connect("gophish.db")


    """
    CREATE TABLE smtp(
        id integer primary key autoincrement,
        user_id bigint,
        interface_type varchar(255),
        name varchar(255),
        host varchar(255),
        username varchar(255),
        password varchar(255),
        from_address varchar(255),
        modified_date datetime default CURRENT_TIMESTAMP,
        ignore_cert_errors BOOLEAN
    );

    CREATE TABLE headers(
        id integer primary key autoincrement,
        key varchar(255),
        value varchar(255),
        "smtp_id" bigint
    );
    """

    email = sys.argv[1]
    date = datetime.now(timezone.utc)

    cursor = db.cursor()

    res = cursor.execute("SELECT * FROM smtp WHERE from_address = ?", [email])
    entry = res.fetchone()

    if entry == None:
        cursor.execute("""INSERT INTO smtp(user_id,interface_type,name,host,username,password,from_address,modified_date,ignore_cert_errors) VALUES (?,?,?,?,?,?,?,?,?)""", (1, "SMTP", "SMTP - %s" % email, "127.0.0.1:25", "", "", email, date, True))

        smtp_id = cursor.lastrowid

        cursor.execute("""INSERT INTO headers(key,value,smtp_id) VALUES (?,?,?)""", ("List-Unsubscribe", "mailto:%s" % email, smtp_id))
        cursor.execute("""INSERT INTO headers(key,value,smtp_id) VALUES (?,?,?)""", ("Message-Id", "<{{.RId}}@%s>" % email.split('@')[-1], smtp_id))
        cursor.execute("""INSERT INTO headers(key,value,smtp_id) VALUES (?,?,?)""", ("X-Mailer", "Microsoft office outlook, build 17.551210", smtp_id))

        db.commit()



if __name__ == '__main__':
    main()
