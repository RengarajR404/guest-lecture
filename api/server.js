const express = require('express');
const bcrypt = require('bcrypt');
const {MongoClient} = require('mongodb');
const jwt = require('jsonwebtoken');
const nodemailer =  require('nodemailer');
const randomstring = require('randomstring');
const cors = require('cors');
const bodyParser = require('body-parser');
const {authenticate} = require('../middleware/authenticate')
const {json} = require('express');
const session = require("express-session");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 4000;
const secret_key = "9JxnBAyCMKcTWc0LdD7fI48gcJo1G2Lo78+SVpd56/c=";
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(
    session({
        secret: secret_key, // Replace with your secret key
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Set to true if using HTTPS
            maxAge: 86400000, // Cookie expiration time (in milliseconds)
        },
    })
);


const uri = "mongodb://localhost:27017/";

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const client = new MongoClient(uri);
        await client.connect();
        const database = await client.db("Guest_Lecture");
        const user_info = await database.collection("User_information");

        const user = await user_info.findOne({username: username});
        req.session.user = user;
        if (!user) {
            console.log("User not found");
            return res.status(401).send('User not found');
        }
        const isPasswordCorrect = await  bcrypt.compare(password, user.password);
        console.log(isPasswordCorrect);
        if (!isPasswordCorrect) {
            console.log("Username or password incorrect");
            return res.status(401).send('Username or password incorrect');
        }
        console.log("password correct");
        res.send("User Login successful");
    }
    catch (e) {
        console.error(e);
    }
});
app.post("/register", async (req, res) =>{
    const {username, name, email,  role, password, areas_of_interest, department } = req.body;
    const client = new MongoClient(uri);
    await client.connect();
    const database = await client.db("Guest_Lecture");
    const user_info = await database.collection("User_information");
    const user = await user_info.findOne({username: username});
    if(user){
        res.status(503).send("User already present in the system Please login");
    }
    else{

        if(role === 'faculty'){
            try{
            await user_info.insertOne({
                username: username,
                name: name,
                email : email,
                role: "faculty",
                password: await bcrypt.hash(password, 10),
                areas_of_interest: areas_of_interest,
                verified_otp: false,
                department: department,
                lectures_taken: [],
            });
            res.status(200).send("User successfully created, Please verify the OTP sent to your mail address");
            }
            catch {
                console.log("Error "+ e);
                res.status(500).send("Internal Server Error");
                }
        }
        else{
            try{
                await user_info.insertOne({
                    username: username,
                    name: name,
                    email: email,
                    role: "student",
                    password: await bcrypt.hash(password, 10),
                    areas_of_interest: areas_of_interest,
                    verified_otp: false,
                    department: department,
                    lectures_attended: [],
                });
                res.status(200).send("User successfully created, Please verify the OTP sent to your mail address");
            }
            catch(e) {
                res.status(500).send("Internal Server Error");

            }
        }
    }


});
/*
function generateToken(username, role) {
    const userData = {
        username: username,
        role: role,
    };
     const token =  jwt.sign(userData, secret_key, {expiresIn : '1h'});
     return token;
}

 */

function verifyToken(token, username, role){
    try {
        const data = jwt.verify(token, secret_key);
        const exp_time = data.exp;
        const currentTime = Date.now() / 1000;
        return data.username === username && data.role === role && currentTime < exp_time;
    }
    catch (e) {
        console.log(e);
        return false;
    }

}

app.get("/dashboard",  (req, res) =>{
    try {
        const {username, role} = req.body;
        const check_role = req.session.user.role
        const check_username = req.session.user.username;
        const valid = check_role === role;
        const valid2 = check_username === username

        if (!(valid && valid2)) {
            res.status(503).send("Not authorised");
        } else {
            res.status(200).send({
                "username": req.session.user.username,
                "role": req.session.user.role,
                "areas_of_interest": req.session.user.areas_of_interest,
                "department": req.session.user.department,
                "lectures_attended": req.session.user.lectures_attended,
                "lectures_taken": req.session.user.lectures_taken
            });
        }
    }
    catch (e) {
        res.status(503).send("Not authorised to use");
    }

});


app.get("/events", async (req, res) =>{

    try{
            const client = new MongoClient(uri);
            await client.connect();
            const database = await client.db("Guest_Lecture");
            const collection = await database.collection("Lectures");
            const data = await collection.find().toArray();
            res.status(200).send(data)

        
    }
    catch (e) {
        console.log(e);
        res.status(500).send("Internal Server Error");
    }

});


app.post("/create-event", async (req, res) =>{
    /*
    {
  "lecture_name": "Introduction to Jira",
  "lecture_given_by": "Dr. ABC",
  "position": "TCS Project Lead",
  "About": "Loreum Ipsum Loreum Ipsum Loreum Ipsum Loreum IpsumLoreum Ipsum Loreum IpsumLoreum Ipsum Loreum Ipsum Loreum Ipsum Loreum Ipsum",
  "Payment": false,
  "Fee": 0,
  "Date": "2023-12-06T09:30:00Z",
  "Venue": "Online",
  "link": "www.microsoft-teams.com",
  "created_by": "administrator",
  "registered_students": [],
  "attended_students": []
}
     */
    const {lecture_name, lecture_given_by, position, about, payment, fee, date, venue, link, created_by} = req.body
    try{
        if(req.session.user.role === 'student') {
            res.status(401).send("Student cannot create events");
        }
        const client = new MongoClient(uri);
        await client.connect();
        const database = await client.db("Guest_Lecture");
        const lecture = await database.collection("Lectures");
        const check = await lecture.findOne({lecture_name : lecture_name});
        if(check){
            res.status(503).send("Event with this name already exists");
        }

        else{
            if(payment === false) {
                await lecture.insertOne(
                    {
                        lecture_name: lecture_name,
                        lecture_given_by: lecture_given_by,
                        position: position,
                        About: about,
                        Payment: false,
                        Fee: 0,
                        Date: date,
                        Venue: venue,
                        link: link,
                        created_by: req.session.role,
                        registered_students: [],
                        attended_students: []
                    }
                );
            }
            else{
                await lecture.insertOne(
                    {
                        lecture_name: lecture_name,
                        lecture_given_by: lecture_given_by,
                        position: position,
                        About: about,
                        Payment: true,
                        Fee: fee,
                        Date: date,
                        Venue: venue,
                        link: link,
                        created_by: req.session.role,
                        registered_students: [],
                        attended_students: []
                    }
                );
            }
            res.status(200).send("Event created successfully");
        }

    }
    catch (e) {
        console.error(e);
        res.status(503).send("Internal Server Error");
    }

});

app.get("/:faculty/:course_name/view-registrations", async (req, res) =>{
    const faculty_name = req.params.faculty;
    const course_name =  req.params.course_name;
    if(req.session.user.username !== faculty_name){
        res.status(403).send("You are not authorised to view this page");
    }
    console.log("We are here");
    try{
        const client = new MongoClient(uri);
        await client.connect();
        const database = await client.db("Guest_Lecture");
        const lectures = await database.collection("Lectures");

                }
            }
        );
    }
    catch (e) {
        console.error(e);
        res.status(503).send("Internal Server Error")
    }
});

app.post("/events/register-event/payment", async (req, res)=>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, role);
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{

        }

    }
    catch (e) {

    }


});
function send_otp(email, username){
    try {
        // Generate the OTP
        const otp = randomstring.generate({
            length: 6,
            charset: 'alphanumeric'
        });
        console.log(otp);

        // Create a Nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'guest.lecture.amrita@gmail.com',
                pass: 'eryrrqrhnhaskaaw'
            }
        });

        // Define the email options
        const mailOptions = {
            from: 'guest.lecture.amrita@gmail.com',
            to: email,
            subject: 'Your OTP for verification of your account in Amrita Guest lecture platform',
            text: `Dear , ${username},\n\tYour OTP for verifying your account in  Guest lecture application is\n <b>,  ${otp} </b>\n.
                                        If you have not requested for an OTP, kindly ingnore this email.`
        };

        // Send the email
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });
        return otp;
    }
    catch (e) {
        console.error(e);
    }

}

function verify_otp( otp_sent, otp_rec){
    return otp_sent === otp_rec ? true : false;
}

app.post('/send-otp', async (req, res) =>{
    const {username, email} = req.body;
    const otp = send_otp(email, username);
    req.session.otp = otp;

    if(!otp){
        res.status(503).send("Error in server");
        const client = new MongoClient(uri);
        await client.connect();
        const database = await client.db("Guest_Lecture");
        const collection = await database.collection("User_information");

    }
    else{
        res.status(200).send("OTP sent successfully");
    }



});

// Verify the OTP
app.post('/verify-otp', (req, res) => {
    const {username, email, otp} = req.body
    console.log(req.session.otp);
    if (otp && otp === req.session.otp) {
        req.session.otp = undefined;
        res.status(200).send('OTP verified.');

    } else {
        res.status(400).send('Invalid OTP.');
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const courseName = req.params.course_name;
        const folderPath = path.join(__dirname, '../uploads', courseName);

        // Create the folder if it doesn't exist
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true });
        }

        cb(null, folderPath);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});

const upload = multer({ storage });

app.post('/uploads/:course_name', upload.single('file'), (req, res) => {
    if (!req.file) {
        res.status(500).send('File upload failed');
    } else {
        res.status(200).send('File uploaded successfully!!!');
    }
});




app.get('/files/:course_name', (req, res) => {
    const courseName = req.params.course_name;
    const directoryPath = path.join(__dirname, '../uploads', courseName);

    fs.readdir(directoryPath, (err, files) => {
        if (err) {
            console.error('Error reading directory:', err);
            res.status(500).send('Internal Server Error');
        } else {
            const fileURLs = files.map((file) => {
                return `${req.protocol}://${req.get('host')}/downloads/${courseName}/${file}`;
            });
            res.status(200).send(fileURLs.join('\n'));
        }
    });
});

app.use('/downloads', express.static(path.join(__dirname, '../uploads')));








app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
