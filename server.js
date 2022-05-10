const express = require("express");
const app = express();
const port = 5000;
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const ddbw = require("ddbw");
const fs = require("fs");
const path = require("path");
const formidable = require("formidable");
const bcrypt = require("bcrypt");
const saltRounds = 10;

ddbw.init();
ddbw.newDatabase("logicreviewsdb");

var connection = new ddbw.Connection("logicreviewsdb");

connection.newCollection("users");
connection.newCollection("movies");

app.set("view engine", "ejs");

app.use(express.static(__dirname + "/public"));

app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser());

var bannedCharacters = [" ", "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^", "`", "{", "|", "}", "~"]

app.get("/", (req, res) => {
    var userCookie = req.cookies["userCookie"];
    var documents = connection.listAllDocuments("movies");
    var movies = [];

    for (var i = 0; i < documents.length; i++) {
        var movie = connection.getDoc("movies", documents[i]);

        movies.push(movie);
    }

    if (userCookie == null) {
        userCookie = false;
    }

    res.render("index", {token: userCookie.token, movies: movies});
});

app.get("/index", (req, res) => {
    return res.redirect("/");
});

app.get("/login", (req, res) => {
    var userCookie = req.cookies["userCookie"];
    
    if (userCookie == null) {
        res.render("login");
    } else {
        return res.redirect("/");
    }
});

app.get("/signup", (req, res) => {
    var userCookie = req.cookies["userCookie"];

    if (userCookie == null) {
        res.render("signup");
    } else {
        return res.redirect("/");
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("userCookie")
    
    return res.redirect("/");
});

app.get("/redirect/:url", (req, res) => {
    res.render("redirect", {url: req.params.url});
});

app.get("/404", (req, res) => {
    res.render("404");
});

app.get("/submitmovie", (req, res) => {
    var userCookie = req.cookies["userCookie"];
    var documents = connection.listAllDocuments("users");
    
    if (userCookie != null) {
        var user = connection.getDoc("users", documents.find(user => connection.getDoc("users", user).data.token == userCookie.token));

        if (user != undefined) {
            if (user.data.role == "admin") {
                return res.render("submitmovie", {token: userCookie.token});
            }
        }
    }
    
    return res.redirect("/404");
});

app.get("/movie/:movie", (req, res) => {
    var userCookie = req.cookies["userCookie"];

    if (userCookie == null) {
        userCookie = false;
    }
    
    var movie = connection.getDoc("movies", req.params.movie);
    
    if (movie.exists) {
        res.render("movie", {token: userCookie.token, movie: movie});
    } else {
        return res.redirect("/404");
    }
});

app.post("/api/login", (req, res) => {
    var user = connection.getDoc("users", req.body.username);

    if (user.exists) {
        bcrypt.compare(req.body.password, user.data.password).then(function(result) {
            if (result) {
                res.cookie("userCookie", {token: user.data.token}, {
                    maxAge: 86400 * 1000,
                    httpOnly: true,
                    secure: true
                });
    
                return res.redirect("/");
            } else {
                return res.redirect("/login?error=incorrectPassword");
            }
        });
    } else {
        return res.redirect("/login?error=incorrectUsername");
    }
});

app.post("/api/register", (req, res) => {
    if (req.body.username.length >= 3 && req.body.username.length <= 20 && req.body.email.length >= 6 && req.body.email.length <= 256 && req.body.password.length >= 8 && req.body.password.length <= 256) {
        var users = connection.listAllDocuments("users");

        if (!users.includes(req.body.username)) {
            if (!connection.getDoc("users", users.find(user => connection.getDoc("users", user).data.email == req.body.email)).exists) {
                for (var i = 0; i < bannedCharacters.length; i++) {
                    if (req.body.username.includes(bannedCharacters[i])) {
                        return res.redirect("/signup?error=usernameContainsBannedCharacters");
                    } else if (i == bannedCharacters.length - 1) {
                        bcrypt.hash(req.body.password, saltRounds, function(err, passwordHash) {
                            bcrypt.hash(req.body.email, saltRounds, function(err, emailHash) {
                                connection.createDoc("users", req.body.username, {
                                    email: emailHash,
                                    username: req.body.username,
                                    password: passwordHash,
                                    token: crypto.randomBytes(16).toString("base64url")
                                });
                            });
                        });
                    }
                }
            } else {
                return res.redirect("/signup?error=emailAlreadyUsed");
            }
        } else {
            return res.redirect("/signup?error=usernameTaken");
        }
    } else {
        return res.redirect("/signup?error=invalidLength");
    }

    return res.redirect("/");
});

app.post("/api/submitmovie", (req, res) => {
    var userCookie = req.cookies["userCookie"];
    var documents = connection.listAllDocuments("users");
    var user = connection.getDoc("users", documents.find(user => connection.getDoc("users", user).data.token == userCookie.token));

    const form = new formidable.IncomingForm();

    if (userCookie != null && user != undefined) {
        if (user.data.role == "admin") {
            form.parse(req, function(err, fields, files) {
                var oldPath = files.image.filepath;
                var newPath = path.join(__dirname, "/public/images/") + fields.id + path.extname(files.image.originalFilename);
                var rawData = fs.readFileSync(oldPath);
                
                fs.writeFile(newPath, rawData, function (err) {
                    if(err) console.log(err);
                    return;
                });
                
                connection.createDoc("movies", fields.id, {
                    name: fields.name,
                    id: fields.id,
                    image: fields.id + path.extname(files.image.originalFilename)
                });
            });
            
            return res.redirect("/redirect/index");
        }
    }

    return res.redirect("/404");
});

app.use((req, res, next) => {
    res.status(404).redirect("/404");
});

app.listen(port);