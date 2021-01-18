require('dotenv').config(); // reikalingas dotenv package naudojimui;
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose"); //1)
const session = require('express-session'); //1$
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy; //use it as a passport strategy; 1%
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate'); //1&

const app = express();

app.use(express.static("public")); //norint naudoti statini folderi "public" (pvz.: img ar css)
// set the view engine to ejs
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// Sesiju naudojimas su tam tikra konfiguracija. //2$
app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: false
}));

// passport yra naudojamas autentifikacijai. Inicializuojam passport:
app.use(passport.initialize()); //3$
// to use a passport to managing(valdyti) our session
app.use(passport.session()); //4$


mongoose.connect('mongodb://localhost:27017/userDB', { //2)
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true); //9$


// Create user schema (JS Object created from mongoose Schema class) 2#
const userSchema = new mongoose.Schema({ //3)
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose); //5$
userSchema.plugin(findOrCreate); //1&

// to set up a new User model
const User = new mongoose.model("User", userSchema); //4)

// --------use passport-local-mongoose to create a local login
//strategy and set passport to serialize and deserialize our user
passport.use(User.createStrategy()); //6$

// passport.serializeUser(User.serializeUser()); //7$
// passport.deserializeUser(User.deserializeUser()); //8$

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//using passtort to authenticate our users using google OAuth; 2%
passport.use(new GoogleStrategy({ //to login our user
    clientID: process.env.CLIENT_ID, //from .env file
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", //from google Credentials-OAuth 2.0 Client IDs
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //required !!
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);

    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) { //2&
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    //  console.log(profile);
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});
//----------------------google----------------------------
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

//--------------------facebook-------------------------------
app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

//----------------Nukreipimui i login ir register----------------
app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});
//-------------------secrets isvedimui puslapyje-----------------
app.get("/secrets", function(req, res) {
User.find({"secret": {$ne: null}}, function(err, foundUsers){//Looks throw Users collection, secrets field where secret is not equal to null
  if (err){
    console.log(err);
  } else {
    if(foundUsers){
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  }
});
});

//---------------------ADMIN-------------------------------------
app.get("/admin", function(req, res) {
User.find({"secret": {$ne: null}}, function(err, foundUsers){ //Looks throw Users collection, secrets field where secret is not equal to null
  if (err){
    console.log(err);
  } else {
    if(foundUsers){
      res.render("admin", {usersWithSecrets: foundUsers});
    }
  }
});
});


app.post("/delete", function(req, res) { //trynimui
  const checkedItemId = req.body.checkbox;

      //to find the list Document with current id and update it
    User.findOneAndUpdate({_id: checkedItemId}, {$unset: {secret: ""}}, function(err) { // $unset operator deletes a particular field
      if (!err){
            console.log("Succesfully deleted checked item.");
            res.redirect("/admin");
      }
    });
});

//-----------------------Tikrina, ar identifikuota----------------------------
app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) { //to check authenticate or not
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//-----------------------Submit Secret----------------------------
app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  console.log(req.user.id); //I will find the user and add the secret they submitted to secretField to the schema
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});
//---------------------Log Out-------------------------------------
    app.get("/logout", function(req, res) {
      req.logout();
      res.redirect('/');
    });

//-----------------------Registration------------------------------
    //register post route 5)
    app.post("/register", function(req, res) { // !* Serveris gauna duomenis is musu web page,
      //kuriame esame. Pvz /register (naudojant register.ejs - <form action="/register" method="POST">)

      User.register({
        username: req.body.username
      }, req.body.password, function(err, user) {
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function() {
            res.redirect("/secrets");
          });
        }
      }); //register - from passport-local-mongoose package
    });

//--------------------Log In--------------------------------------
    app.post("/login", function(req, res) {
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });

      // to log in and authenticate it. Method comes from passport
      req.login(user, function(err) {
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function() {
            if (req.body.username == "admin@admin.com"){
                res.redirect("/admin");
            } else{
                res.redirect("/secrets");
            }
          });
        }
      });
    });
//----------------------------------------------------------------
    //Privaloma portui nustatyti
    app.listen(3000, function() {
      console.log("Server started on port 3000");
    });
