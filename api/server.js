const express = require('express');
const bcrypt = require('bcrypt');
const {MongoClient} = require('mongodb');
const jwt = require('jsonwebtoken');
const nodemailer =  require('nodemailer');
const randomstring = require('randomstring');
const cors = require('cors');
const bodyParser = require('body-parser');
const {authenticate} = require('../middleware/authenticate')
const {json} = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const multer = require('multer');
const path = require('path');
const { promisify } = require('util');
const fs = require('fs');
const exec = promisify(require('child_process').exec);
const crypto = require('crypto');
const {genSalt} = require("bcrypt");
const upload = multer({ dest: 'uploads/' });
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
    const {username, role} = req.body;
    const check_role = req.session.user.role
    const check_username =  req.session.user.username;
    const valid = check_role === role;
    const valid2 = check_username === username

    if(!(valid && valid2)){
       res.status(503).send("Not authorised");
    }
    else{
        res.status(200).send(req.session.user);
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

app.post("/events/register-event", async (req, res) =>{

    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "student");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{

            res.status(200);
            res.send("You can view this page");
        }

    }
    catch (e) {

    }
});


app.post("/faculty/create-event", async (req, res) =>{
    const {username, role, event_details} = req.body;
    try{
        if(req.session.user.role === 'student') {
            res.status(503).send("Student cannot create events");
        }
        if(! (req.session.user.username === username && req.session.user.role === role)) {
            res.status(503).send("User is not correctly signed in")
        }
        else{
            

        }

    }
    catch (e) {

    }

});

app.post("/faculty/view-registrations", async (req, res) =>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "faculty");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            res.status(200);
            res.send("You are authorized to view this page");
        }

    }
    catch (e) {

    }

});

app.post("/admin/dashboard", async (req, res) =>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "admin");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            res.status(200);
            res.send("You are authorized to view this page");
        }

    }
    catch (e) {

    }

});

app.post("/faculty/dashboard", async (req, res)=>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "faculty");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            res.status(200);
            res.send("You are authorized to view this page");
        }

    }
    catch (e) {

    }

});
app.post("/admin/view-users", async(req, res) =>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "admin");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            const client = new MongoClient(uri);
            await client.connect();
            const database = await client.db("Guest_Lecture");
            const collection = await database.collection("User_information");
            const data = await collection.find({role:{$in : ["student", "faculty"]}}).toArray();
            res.status(200);
            console.log(data);
            res.status(200);
            res.send(data);
        }

    }
    catch (e) {
        console.log(e);
    }
});

app.post("/admin/create-events", async (req, res)=>{
    const {username, role, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "administrator");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            res.status(200);
            res.send("You are authorized to view this page");
        }

    }
    catch (e) {

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



// Configure static file serving
app.use('/public', express.static(path.join(__dirname, 'public')));

// Function to check if the file extension is executable
function isExecutableExtension(filename) {
    const executableExtensions = ['.exe', '.sh', '.bat', '.cmd', '.py'];
    const ext = path.extname(filename).toLowerCase();
    return executableExtensions.includes(ext);
}

// Endpoint for file upload

// Configure Multer to store files in the desired folder
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Extract the folder name from the request URL
        const folderName = req.params.folderName;
        // Set the destination folder path
        const folderPath = path.join(__dirname, 'uploads', folderName);
        // Call the callback function with the destination folder path
        cb(null, folderPath);
    },
    filename: (req, file, cb) => {
        // Use the original file name as the stored file name
        cb(null, file.originalname);
    },
});



app.post('/uploads/:folderName', upload.single('file'), (req, res) => {
    // File has been uploaded and stored in the specified folder
    res.send('File uploaded successfully.');
});

app.listen(4000, () => {
    console.log('Server is running on port 4000');
});

// Endpoint for viewing a file
app.get('/files/:filename', (req, res, next) => {
    let filename = req.params.filename;

    // Prevent directory traversal by normalizing the filename
    filename = path.normalize(filename);

    // Prevent file traversal by checking the filename
    if (filename.includes('..')) {
        res.status(400).send('Invalid file name');
        return;
    }

    const filePath = path.join(__dirname, 'uploads', filename);

    // Check if the file exists
    fs.access(filePath, fs.constants.R_OK, (err) => {
        if (err) {
            res.status(404).send('File not found');
            return;
        }

        // Prevent command injection by sanitizing the filename
        const sanitizedFilename = filename.replace(/[^a-z0-9\-_.]/gi, '');

        // Check if the file has an executable extension
        if (isExecutableExtension(filename)) {
            res.status(403).send('File cannot be executed');
            return;
        }

        // Serve the file using the sanitized filename
        res.sendFile(sanitizedFilename, { root: path.join(__dirname, 'uploads') }, (err) => {
            if (err) {
                next(err);
            }
        });
    });
});









app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
