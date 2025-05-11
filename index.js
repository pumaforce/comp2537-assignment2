require('dotenv').config(); 
require('./utils.js'); 
const express = require('express');
const session = require("express-session");
const bcrypt = require("bcrypt");
const MongoStore = require("connect-mongo");
const Joi = require("joi");

const saltRounds = 12;
// 1 hours
const expireTime = 1 * 60 * 60 * 1000; 

const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');

const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SECRET;
const mongodb_user = process.env.MONGODB_USER; 
const mongodb_password =  process.env.MONGODB_PASSWORD; 
const mongodb_host = process.env.MONGODB_HOST; 
const mongodb_database = process.env.MONGODB_DATABASE;

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection("users");

let users = [];

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use(express.urlencoded({ extended: false }));   
app.use(express.static(__dirname + "/public"));

app.get("/", function(req, res) {
    res.render('index', {authenticated: req.session.authenticated, name: req.session.name});
});

app.get("/logout", function(req, res) {
    if (req.session) {
        req.session.destroy();
        res.redirect("/");
    }
});

app.get("/signup", function (req, res) {
    res.render('signup');
});

app.post("/submitUser", async (req, res) =>{
    let name = req.body.name;
    let username = req.body.username;
    let password = req.body.password;

    if (name == null || username == null || password == null || name == "" || username == "" || password == "") {
        res.render('submitUser', {
            name: name,
            username: username,
            password: password,
            sqlInjection: false
        });
        return;
    }

    const schema = Joi.object(
    {
        name: Joi.string().alphanum().max(20).required(),
        username: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required()
    });
    const validationResult = schema.validate({name, username, password});
    if (validationResult.error != null) {
        res.render('submitUser', {
            name: name,
            username: username,
            password: password,
            sqlInjection: true
        });
        return;
    }
    let hashedPassword = bcrypt.hashSync(password, saltRounds);
    users.push({
        name: name,
        username: username,
        password: hashedPassword
    });
    
    await userCollection.insertOne({username: username, password: hashedPassword, name: name});
    
    req.session.authenticated = true;
    req.session.username = username;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/");

});

// server side logging in check
app.post("/loggingin", async(req, res) =>{
    let username = req.body.username;
    let password = req.body.password;
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });
        const validationResult = schema.validate({username, password});
        if (validationResult.error != null) {
            res.redirect("/login?error=A NoSQL injection attack was detected!!");
            return;
        }

    const users = await userCollection.find({username: username}).project({username: 1, password: 1, name: 1}).toArray();
    if (users.length != 1) {
        console.log("User not found");
        res.redirect("/login?error=User not found");
        return;
    } else {
        
        let result = await bcrypt.compare(password, users[0].password);
        if (result === true) {
            req.session.authenticated = true;
            req.session.username = users[0].username;
            req.session.name = users[0].name;
            req.session.cookie.maxAge = expireTime;
            res.redirect("/");
            return;
        } else {
            console.log("Incorrect password");
            res.redirect("/login?error=Incorrect password");
            return;
        }
    }
});

app.get("/members", validateSession, function(req, res) {
    let randomNumber = Math.floor(Math.random() * 3);
    res.render('members', {name: req.session.name, randomNumber: randomNumber});
});
function validateSession(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect("/login");
    }
}
app.get("/login", function(req, res) {
    res.render('login', {error: req.query.error});
});

app.get('*', (req, res) => {
    res.render('404');
  });

app.listen(
    PORT, 
    () => { console.log(`Server is running on http://localhost:${PORT}`);
});
