const express = require('express');
const bcrypt = require('bcrypt');
const {MongoClient} = require('mongodb');
const jwt = require('jsonwebtoken');
const nodemailer =  require('nodemailer');
const randomstring = require('randomstring');
const cors = require('cors');
const bodyParser = require('body-parser');
//const {authenticate} = require('../middleware/authenticate')
const {json} = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const multer = require('multer');
const path = require('path');
const { promisify } = require('util');
const fs = require('fs');
const exec = promisify(require('child_process').exec);
const crypto = require('crypto');
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
        console.log(user.username);
        console.log(user.role);
        req.session.username = user.username;
        req.session.role = user.role;
        if (!user) {
            console.log("User not found");
            return res.status(401).send('User not found ');
        }
        const isPasswordCorrect = await  bcrypt.compare(password, user.password);
        console.log(isPasswordCorrect);
        if (!isPasswordCorrect) {
            console.log("Username or password incorrect");
            return res.status(401).send('Username or password incorrect');
        }
        console.log("password correct");
        // If the password is correct, create a token and send it back to the client
        const token = await generateToken(user.username, user.role);
        console.log(token);
        session({
            secret: secret_key,
            username: user.username,
            role: user.role
        })
        //res.cookie('session_id', token, { maxAge: 900000, secure: false, sameSite: 'None' }).status(200);
        res.send("User Login successful");
    }
    catch (e) {
        console.error(e);
    }
});
app.post("/register", async (req, res) =>{

});
function generateToken(username, role) {
    const userData = {
        username: username,
        role: role,
    };
     const token =  jwt.sign(userData, secret_key, {expiresIn : '1h'});
     return token;
}

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

app.post("/dashboard",   async (req, res) =>{
    const {username, role, session_id} = req.body;
    try{
        const valid = await verifyToken(session_id, username, role);
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            console.log(username);
            console.log(role);
            const client = new MongoClient(uri);
            await client.connect();
            const database = await client.db("Guest_Lecture");
            const user_info = await database.collection("User_information");
            const user = await user_info.findOne({username: username});
            const faculty = await user_info.find({role:faculty});
            if (!user) {
                console.log("User not found");
                return res.status(401).send('User not found');

            } else {
                if(role === "student"){
                    const details = {
                        "username" : user.username,
                        "role" : user.role,
                        "areas_of_interest" : user.areas_of_interest,
                        "department" : user.department,
                        "Lectures_attended" : user.lectures_attended
                    }

                }
                else if(role ==='faculty'){
                    const details = {
                        "username": user.username,
                        "role": user.role,
                        "areas_of_interest": user.areas_of_interest,
                        "department": user.department,
                        "lectures_taken": user.lectures_taken
                    }
                }
                else if(role ==='admin'){
                    //const details
                }
                
                return res.status(200).send(details);
            }
        }
    }
        catch (e) {
            console.error(e);
            res.status(500).send("Internal Server error");
        }

});


app.post("/events", async (req, res) =>{
    const {username, session_id} = req.body;
    try{
        const valid = verifyToken(session_id, username, "student");
        if(!valid){
            res.status(403);
            res.send("You are not authorized to view this page");
        }
        else{
            const client = new MongoClient(uri);
            await client.connect();
            const database = await client.db("Guest_Lecture");
            const collection = await database.collection("Lectures");
            const data = await collection.find().toArray();
            res.status(200);
            console.log(data);
            res.send(data);
        }
        
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
            text: `Dear , ${username},\n\tYour OTP for verifying your account in Amrita Guest lecture application is,  ${otp}.`
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
        // Clear the OTP from the session
        req.session.otp = undefined;
        res.status(200).send('OTP verified.');
    } else {
        res.status(400).send('Invalid OTP.');
    }
});

const multer = require('multer');
const path = require('path');
const { promisify } = require('util');
const fs = require('fs');
const exec = promisify(require('child_process').exec);
const crypto = require('crypto');


const upload = multer({ dest: 'uploads/' });

// Configure static file serving
app.use('/public', express.static(path.join(__dirname, 'public')));

// Function to generate a random file name
function generateRandomFileName() {
    const randomBytes = crypto.randomBytes(16);
    const uniqueFileName = randomBytes.toString('hex');
    return uniqueFileName;
}

// Function to check if the file extension is executable
function isExecutableExtension(filename) {
    const executableExtensions = ['.exe', '.sh', '.bat', '.cmd'];
    const ext = path.extname(filename).toLowerCase();
    return executableExtensions.includes(ext);
}

// Endpoint for file upload
app.post('/upload', upload.single('file'), (req, res, next) => {
    // Check if a file was uploaded
    if (!req.file) {
        res.status(400).send('No file uploaded');
        return;
    }

    // Generate a random file name
    const uniqueFileName = generateRandomFileName();

    // Handle file upload and rename it
    const tempPath = req.file.path;
    const targetPath = path.join(__dirname, 'uploads', uniqueFileName);

    fs.rename(tempPath, targetPath, (err) => {
        if (err) {
            next(err);
            return;
        }

        res.status(200).send('File uploaded successfully');
    });
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


// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});







app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
