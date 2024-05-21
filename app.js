require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: 'Who did that',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
  cb(null, obj);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOne({ googleId: profile.id })
      .then(user => {
        if (!user) {
          const newUser = new User({
            googleId: profile.id,
            email: profile.emails[0].value
          });
          return newUser.save();
        } else {
          return user;
        }
      })
      .then(user => cb(null, user))
      .catch(err => cb(err));
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect("/secrets");
  }
);

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", async function(req, res) {
  try {
    await new Promise((resolve, reject) => {
      req.logout(function(err) {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
    res.redirect("/login");
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async function(req, res) {
  try {
    const user = await User.register({ username: req.body.username }, req.body.password);
    // Authenticate the user after successful registration
    req.login(user, function(err) {
      if (err) {
        console.error('Error:', err);
        res.status(500).send('Internal Server Error');
      } else {
        res.redirect("/secrets");
      }
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post("/submit", async function(req,res){
  try{
    const submittedSecret = req.body.secret;

    const foundUser = await User.findById(req.user.id); // Corrected method name to findById
    if(foundUser){
      foundUser.secret = submittedSecret; // Corrected variable name to foundUser
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
