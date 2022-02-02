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

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId : String
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
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/facebook',passport.authenticate('facebook', {scope: ["profile","email"]}));

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
        // var context = req.session.context;
        res.render("login", {errMsg: errMsg});
    }
});

app.get("/register", (req,res)=>{
    res.render("register");
});

app.get("/secrets", (req,res)=>{
    if (req.isAuthenticated()){
        res.render("secrets");
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
                res.redirect('/secrets');
            });
        }
    });
});

app.listen(3000, ()=>{
    console.log("Server Running on Port 3000!");
});