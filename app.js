require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
var findOrCreate = require('mongoose-findorcreate');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
// passport-local not needed to be required because passport-local-mongoose already does that
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-peter:test123@cluster0.a0f5b.mongodb.net/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId : String,
    facebookId : String,
    facebookName: String,
    secret: String
});

userSchema.plugin(findOrCreate);
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

var errMsg = "";

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  (accessToken, refreshToken, profile, cb) => {
    console.log("User:",profile.displayName," logged in successfully using google. Email:", profile._json.email);
    User.findOrCreate({username: profile.emails[0].value,googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  (accessToken, refreshToken, profile, cb) => {
        User.findOne({facebookId: profile._json.id}, (err, foundUser)=>{
            if(err){
                console.log(err);
            } else{
                if (foundUser === null){
                    const user = new User({
                        facebookId: profile._json.id,
                        facebookName: profile._json.name
                    });
                    user.save();
                    console.log("New User Created using Facebook: Facebook Id: ",profile._json.id,"\n\t\t\t\tFacebook Name: ",profile._json.name);
                    return cb(err, foundUser);
                } else {
                    console.log("User Sign In Using Facebook: Facebook Id: ",profile._json.id,"\n\t\t\t\tFacebook Name: ",profile._json.name);
                    return cb(err, foundUser);
                }
            }
        }); 
  }
));

app.get('/auth/facebook',passport.authenticate("facebook", {scope: "public_profile"}));

app.get('/auth/facebook/secrets',passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res)=> {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/", (req,res)=>{
    res.render("home");
    errMsg = "";
});

app.get("/auth/google", passport.authenticate("google", {scope: ["profile","email"]} ));

app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login", (req,res)=>{
    if(req.isAuthenticated()){
        res.redirect("/secrets");
    } else {
        res.render("login", {errMsg: errMsg});
    }
});

app.get("/register", (req,res)=>{
    res.render("register");
});

app.get("/secrets", (req,res)=>{
    if (req.isAuthenticated()){
        User.find({secret: {$ne: null}}, (err,usersWithSecret)=>{
            if(err){
                console.log(err);
            } else {
                res.render("secrets", {usersWithSecret: usersWithSecret});
            }
        })
    } else {
        res.redirect("/login");
    }
});

app.get("/submit", (req,res)=>{
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req,res)=>{
    req.logout();
    res.redirect("/");
});

app.post("/register", (req,res)=>{
    User.register({username: req.body.username}, req.body.password, (err,user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req,res, ()=>{
                console.log("New Local User Created : UserName: ",req.body.username);
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req,res)=>{
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, (err)=>{
        if(err){
            console.log(err);
        } else {
            errMsg = "Email Or Password Are Incorrect.";
            passport.authenticate("local",{failureRedirect: '/login'})(req,res, ()=>{
                console.log("Local User Signed In : UserName: ",req.body.username);
                res.redirect('/secrets');
            });
        }
    });
});

app.post("/submit", (req,res)=>{
    const secret = req.body.secret;
    User.findOneAndUpdate({_id: req.user.id}, {secret: secret} ,(err,docs)=>{
        if(err){
            console.log(err);
        } else {
            console.log("Secret Successfully Added!");
            res.redirect("/secrets");
        }
    })
});

app.listen(3000, ()=>{
    console.log("Server Running on Port 3000!");
});