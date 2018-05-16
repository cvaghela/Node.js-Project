# Node.js Project

Follow the steps to run this Project on your computer:

Step 1: Install and setup Mongo DB on your Computer (Video Tutorial: https://www.youtube.com/watch?v=DX15WbKidXY&index=26&list=WL&t=6s) [This step needs to be performed only once]:

1.) Download the “Community Server” version of the Mongo DB on your Computer. (https://www.mongodb.com/download-center?jmp=nav#community)

2.) Extract the downloaded file

3.) Rename the extracted folder to ‘mongodb’ and then move it to the users/local/ directory. (It may vary from system to system)

4.) Open your terminal.

5.) Make ‘mongodb’ your current working directory. (For this case: cd “users/local/mongodb”)

6.) Type the command and press enter: sudo mkdir -p /data/db (‘sudo’ command asks you for your computer password)

7.) Make db your current working directory: cd “/data/db”

8.) Type the command and press enter: whoami (This gives you your username)

9.) Type the command and press enter: sudo chown username /data/db (username is the output of whoami from the previous step.) (This step gives permission to the current directory /data/db).

10.) Make you home directory your current working directory by the following command: cd

11.) Find file named ‘.bash_profile’ with the following command: ls -al

12.) If you don’t find this file, then create the file with the following command: touch .bash_profile

13.) Open this file: open .bash_profile

14.) Copy and paste the following lines in the editor, then save & close it:

export MONGO_PATH=/Users/local/mongodb
export PATH=$PATH:$MONGO_PATH/bin

NOTE: MONGO_PATH may vary from system to system.

15.) Type the following command: source .bash_profile (and then, just restart the terminal)

You are all set.

IMPORTANT: Just run the command ‘mongod’ every time you want to start Mongo DB. This the mongo daemon command that starts up your Mongo DB. Mongo Daemon continues to run even after closing the terminal.

Step 2: Installing Node.js and the modules. [This step needs to be performed only once]

1.) Open your Terminal

2.) Make the project directory (nodeauth1 or nodeauth2) your current working directory (e.g. cd nodeauth1)

3.) Run the following command: sudo npm install

NOTE: Once you enter the password and press enter, it will install Node.js and all the required modules.

Step 3: How to run the project. [This step needs to be performed every time you want to run it]

1.) Open your Terminal

2.) Make the project directory (nodeauth1 or nodeauth2) your current working directory (e.g. cd nodeauth1)

3.) Run the following command: npm start

NOTE: This will start your server and on the console / terminal it will show the port on which it is running.

4.) Open your browser

5.) Type the following in the url: http://localhost:PORT/

NOTE: PORT for nodeauth1 is 3000 and PORT for nodeauth2 is 8080. (These ports will be reflected in the console / terminal once the server is running.)

It is a lot more easier to code if you import the project folder (nodeauth1 or nodeauth2) in the ATOM. ( DOWNLOAD LINK: https://atom.io/ )

That’s it! Have fun coding 😊