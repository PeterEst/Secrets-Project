require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});
userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields: ["password"]});
const User = new mongoose.model("User", userSchema);

app.get("/", (req,res)=>{
    res.render("home");
});

app.get("/login", (req,res)=>{
    res.render("login",{errMsg: ""});
});

app.get("/register", (req,res)=>{
    res.render("register");
});

app.post("/register", (req,res)=>{
    const user = new User({
        email: req.body.username,
        password: req.body.password
    });
    user.save((err)=>{
        if(!err){
            res.render("secrets");
        } else {
            console.log(err);
        }   
    });
});

app.post("/login", (req,res)=>{
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, (err,foundUser)=>{
        if(err){
            console.log(err);
        } else {
            if (foundUser){
                if(foundUser.password === password){
                    res.render("secrets");
                    console.log("Access Approved!");
                } else {
                    console.log("Email Or Password Incorrect!");
                    res.render("login",{errMsg: "Email Or Password Incorrect!"});
                }
            } else {
                console.log("Email Or Password Incorrect!");
                res.render("login",{errMsg: "Email Or Password Incorrect!"});
            }
        }
    });
});

app.listen(3000, ()=>{
    console.log("Server Running on Port 3000!");
});