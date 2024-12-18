# INF2003Proj2_P5
Passenger Management System for INF2003_P5_G31

1.	Introduction
•	Overview of the DBMS
Our Air Passenger Arrival Data Management System addresses challenges in tourism management and economic planning by consolidating fragmented air passenger data into a unified, comprehensive database. This system enables analysis of arrival patterns, integrating information on passengers, countries of origin, length of stay, and airlines. This is a powerful tools for data-driven decision-making. The system's capabilities extend to enhanced resource allocation, targeted marketing campaigns, improved tourist
experiences, and the promotion of sustainable tourism practices.

•	Key Features of the DBMS
o	Create, Read, Update, Delete (CRUD) for passenger data
o	Advanced Features: Analyse Airline Popularity, Analyse Tourism Duration, Analyse Airline Trend

•	Installation Guide for MongoDB Compass
o	Install MongoDB Compass here: https://www.mongodb.com/
o	Once MongoDB is up and running
o	Select “Add New Connections”
o	Copy this link into the URL box: 
mongodb+srv://INF2003:INF2003@cluster0.yib8q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0

![image](https://github.com/user-attachments/assets/0e937486-6218-44fd-9f4a-08b40f184603)

o Click save and connect. Now u have successfully connected into the MongoDB Database.


3.	Getting Started with the DBMS
•	Import the python file into the python IDE 
•	Ensure that libraries tkinter, matplotlib, pandas, numpy, psutil, pymongo, functools, bcrypt, jwt,(For security) are installed before running the code.
•	Once the code is running, you will be greeted with a GUI
•	You will be prompt to login as a user. You can create your own by Clicking “Create New Account”
•	Create a Username and Password then proceed to login into the system
![image](https://github.com/user-attachments/assets/f30a7685-9633-4087-b15f-6899ce2000a4)


•	Log into the system to access it features.

4.	Performing Basic Operations
•	Create New Passenger: Select 'Create New Passenger" and fill in the respective Details
•	Read Data: Select 'Read Passenger Details' select by PID to search.
•	Updating Data: Select 'Update Passenger' to Update passenger details
•	Deleting Data: Select 'Delete Passenger' to delete passenger details from table
•	When any user of the system is accessing any Passenger Management CRUD Functions. A 2nd user would be unable to access these functions for concurrency and protect the data integrity of the database. 

![image](https://github.com/user-attachments/assets/937e5ef8-d1e3-4213-98e2-d3c51e67d50e)


5.	Advanced Operations
•	Analyse Airline Popularity: Select 'Analyse Airline Popularity' to view most popular airline and the chart passenger count for each airlines
•	Analyse Tourism Duration: Select 'Analyse Tourism Duration' to view most common stayed duration and chart to compare each duration range
•	Analyse Airline Trend: Select 'Analyse Airline Trend' to view which airlines is the highest passenger from the respective country of origin.

![image](https://github.com/user-attachments/assets/d5dd84db-ae8f-43de-92ce-abf874ba6570)


