
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate= require("mongoose-findorcreate");

const app=express();

app.set("views", __dirname + "/views");
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(__dirname + "public"));

app.use(session({
    secret: "our secret is exposed",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

/*Connect to mongodb database */
mongoose.connect("mongodb+srv://"+process.env.DB_USERNAME+":"+process.env.DB_PASSWORD+"@cluster0.gpbfq.mongodb.net/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: [{type: String}]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User= new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
    done(null,user.id);
});
passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://vast-journey-16712.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.emails[0].value,googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google",{scope: ["profile","email"]})
);
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login",function(req,res){
    res.render("login");
});
app.get("/register",function(req,res){
    res.render("register");
});
app.get("/secrets",function(req,res){
    
    User.find({"secret:":{$ne:null}}, function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                res.render("secrets",{userWithSecrets: foundUser});
            }
        }
    });
    
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }
    // else{
    //     res.redirect("/login");
    // }
});
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret= req.body.secret;
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret.push(submittedSecret);
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    })
});

app.get('/logout', function (req, res){
    req.session.destroy(function (err) {
      res.redirect('/'); //Inside a callback… bulletproof!
    });
  });
app.post("/register",function(req,res){

    User.register({username: req.body.username},req.body.password ,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
    })
    
});

app.post("/login",function(req,res){
   
    const user= new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    })
});


let port = process.env.PORT;
if(port == null || port == ""){
    port = 3000;
}

app.listen(port,function(){
    console.log("server is running");
});