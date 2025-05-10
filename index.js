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
    if (!req.session.authenticated) {
        let signUpHtml =`<a href="/signup"><button>Sign Up</button></a>`;
        let loginHtml =`<a href="/login"><button>Log in</button></a>`;
        res.send(signUpHtml + `<br /> ` + loginHtml); 
    } else {
        let html = `Hello ${req.session.name} <br /> <br />
            <a href="/members"><button>Go to Memebers Area</button></a><br />
            <a href="/logout"><button>Logout</button></a><br />`;
        res.send(html);
    } 
    
});

app.get("/logout", function(req, res) {
    if (req.session) {
        req.session.destroy();
        res.redirect("/");
    }
    
});

app.get("/signup", function (req, res) {
    const html = `<form action="/submitUser" method="POST">
    <input type="text" name="name" placeholder="Name"><br />
    <input type="text" name="username" placeholder="Username"><br />
    <input type="password" name="password" placeholder="Password"><br />
    <button type="submit">Submit</button>
    </form>`;
    res.send(html);
});

app.post("/submitUser", async (req, res) =>{
    let name = req.body.name;
    let username = req.body.username;
    let password = req.body.password;

    let errorHtml =`<a href="/signup">Try again</a>`;
    if (name === "") {
        res.send("Name is required  <br /><br />" + errorHtml);
        return;
    }
    if (username === "") {
        res.send("Username is required  <br /><br />" + errorHtml);
        return;
    } 
    if (password === "") {
        res.send("Password is required  <br /><br />" + errorHtml);
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
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }
    let hashedPassword = bcrypt.hashSync(password, saltRounds);
    users.push({
        name: name,
        username: username,
        password: hashedPassword
    });
    
    
    console.log(users);
    let usershtml = "";
    for (i = 0; i < users.length; i++) {
        usershtml += `<li>${users[i].username} : ${users[i].password}</li>`;
    }
    await userCollection.insertOne({username: username, password: hashedPassword, name: name});
    let html = `<ul>${usershtml}</ul>`;
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
            res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
            return;
        }

    const users = await userCollection.find({username: username}).project({username: 1, password: 1, name: 1}).toArray();
    console.log(users);
    if (users.length != 1) {
        console.log("User not found");
        res.redirect("/login?error=User not found");
        return;
    } else {
        
        let result = await bcrypt.compare(password, users[0].password);
        console.log(`${result}`) ;
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

app.get("/members", function(req, res) {
    console.log(req.session.authenticated);
    if (!req.session.authenticated) {
        res.redirect("/login");
    } else {
        
        let randomNumber = Math.floor(Math.random() * 3);
        
        let html = `<h1>Hello ${req.session.username}</h1>
        <h2>Dog ${randomNumber}:</h2> <img src='/dog${randomNumber}.png' style='width:450px;'> <br />
        <a href="/logout"><button>Logout</button></a><br />`;  
        res.send(html);
    }
});

app.get("/login", function(req, res) {
    
    let htmlError = "";
    if (req.query.error) {
        htmlError = `<h3 style='color:red;'>${req.query.error}</h3>`;
    }
    const html = `<form action="/loggingin" method="POST">
    <input type="text" name="username" placeholder="Username" required><br />
    <input type="password" name="password" placeholder="Password" required><br />
    <button type="submit">Submit</button><br />
    <a href="/signup">Sign Up</a> <br />
    <a href="/">Home</a>
    </form>${htmlError}`;

    res.send(html);
    
});

app.get('*', (req, res) => {
    res.status(404).send('404 Not Found');
  });

app.listen(
    PORT, 
    () => { console.log(`Server is running on http://localhost:${PORT}`);
});
