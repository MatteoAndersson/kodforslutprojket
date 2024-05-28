//alla npms
const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const mysql = require("mysql2");
const dotenv = require("dotenv");
const path = require("path");
const bcrypt = require("bcryptjs");
const http = require("http").Server(app);

const session = require('express-session');

const io = require("socket.io")(http);

app.use(express.static("./views"));

app.use(bodyParser.urlencoded({extended: false}));

app.use(session({
    secret: 'Matteo123',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));


app.set('view engine', 'hbs')
dotenv.config({path: "./.env"});


const db = mysql.createConnection({
    // databasen hämtas från .env
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

app.use(express.urlencoded({extended: 'false'}))
app.use(express.json())

db.connect((error) => {
    if(error){
        console.log(error);
    } else{
        console.log("Ansluten till MySQL");
    }
});

// Använder mallen index.hbs
app.get("/", (req, res) => {
    res.render("index");
});

// Använder mallen register.hbs
app.get("/register", (req, res) => {
    res.render("register");
});

// Använder mallen login.hbs
app.get("/login", (req, res) => {
    res.render("login");
});


//egen ändring
function isValidEmail(email) {
    // Regex för att kontrollera epostadressens format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}





// Tar emot poster från registeringsformuläret
app.post("/auth/register", async (req, res) => {    
    const { name, email, password, password_confirm } = req.body
    if (password !== password_confirm){
        // egen ändring som kollar om båda lösen är samma
        return res.render('register', {
            message: 'Lösenorden matchar inte'
        })
    }
    if (!name || !email || !password || !password_confirm){
        // egen ändring som kollar om något fällt inte är ifyllt
        return res.render('register', {
            message: 'Alla fält är inte ifyllda'
        })
    }
    if (!isValidEmail(email)) {
        // egen ändring som hanterar fallet där epostadressen inte är i rätt format med hjälp av den tidigare funktionen
        return res.render('register', { message: 'Ej giltig e-postadress' });
    } 


    // alla dessa 4 if statements nedan är för att kolla att password skrivs på rätt sätt
    if (password.length < 8) {
        // Minst 8 tecken krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/\d/.test(password)) {
        // Minst en siffra krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/[a-z]/.test(password)) {
        // Minst en liten bokstav krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/[A-Z]/.test(password)) {
        // Minst en stor bokstav krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10); //hashedPassword är det krypterade lösenordet
    
        // Kontrollera om namnet redan finns i databasen
        const nameExists = await new Promise((resolve, reject) => {
            db.query('SELECT name FROM users WHERE name = ?', [name], (error, result) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(result.length > 0);// Om result är 1 eller mer finns namnet redan i databasen och nameExists blir True och då visar meddelandet "Namnet är upptaget som står 6 rader ner i koden."
                }
            });
        });
    
        if (nameExists) {
            return res.render('register', { message: 'Namnet är upptaget' });
        }
    
        // Kontrollera om epostadressen redan finns i databasen samma sätt som med namn
        const emailExists = await new Promise((resolve, reject) => {
            db.query('SELECT email FROM users WHERE email = ?', [email], (error, result) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(result.length > 0);
                }
            });
        });
    
        if (emailExists) {
            return res.render('register', { message: 'Email är upptaget' });
        }
    
        // Fortsätt med registreringsprocessen om namnet och epostadressen inte finns i databasen
        //lägg till användaren
        db.query('INSERT INTO users SET ?', {name: name, email: email, password: hashedPassword}, (err, result) => {//password sätts till hashedPassword för att lösenordet ska stå som det krypterade lösenordet
            if (err) {
                console.log(err);
                return res.render('register', { message: 'Registrering misslyckades' });
            } else {
                return res.render('register', { message: 'Användare registrerad' });
            }
        });
    } catch (error) {
        console.log(error);
        return res.render('register', { message: 'Något gick fel' });
    }
})

// Tar emot poster från loginsidan
app.post("/auth/login", (req, res) => {   
    const { name, password } = req.body
    

    
    //kollar om namnet finns
    db.query('SELECT userID, password FROM users WHERE name = ?', [name], async (error, result) => {
        if(error){
            console.log(error)
        }
        // Om == 0 så finns inte användaren
        if( result.length == 0 ) {
            return res.render('login', {
                message: "Användaren finns ej"
            })
        }
        const hashedPassword = result[0].password;
        userID = result[0].userID;
        console.log(userID);
        console.log(name)
        console.log("userid");

        try {
            const passMatch = await bcrypt.compare(password, hashedPassword);//om det krypterade lösenordet matchar med det som står utan kryptering så loggas man in
        
            // Kollar om lösenordet matchar det i databasen
            if (passMatch) {
                req.session.authenticated = true;
                req.session.user = {name, userID};
                console.log(req.session.user);
                return res.redirect('/chat');
           } 
           else {
                return res.render('login', {
                    message: "Fel lösenord"
                })
           }
        } catch (error){
            console.log(error)
        }
    });
});

app.get("/chat", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }
    res.render('chat', { name: req.session.user.name });
});
const activeUsers = new Map();

let messages = []



app.get("/meddelanden", (req, res) => {
    // få meddelanden från databasen
    const query = `SELECT q.QuestionID, q.content, q.timestamp, u.name 
                   FROM questions q 
                   JOIN users u ON q.userID = u.userID`;
    db.query(query, (error, results) => {
        if (error) {
            console.error("Error fetching messages:", error);
            res.render("error", { error: "Error fetching messages" });
        } else {
            messages = results;
            
            res.send(messages);
        }
    });
});

io.on("connection", (socket) => {
    socket.on("newMessage", (message) => {
        io.emit("newMessage", message); // Emit to all connected clients
    });
});

// hantera inkommande messages
app.post("/meddelanden", (req, res) => {
    
    const { content } = req.body; //content får sitt värde från form på chat.hbs
    const timestamp = new Date().toLocaleString(); // Current timestamp
    console.log("nameformessage")
    console.log(req.session.user.name)
    console.log(req.session.user.userID)
    const username = req.session.user.name;//username och userid ska tas från session
    const userID = req.session.user.userID;
    console.log(userID)
    console.log(username)
    const message = {name: username, content: content, timestamp: timestamp}
    io.emit("newMessage", message);
    
    
    // lägg in meddelandet i databasen
    const query = "INSERT INTO questions (userID, content, timestamp) VALUES (?, ?, ?)";
    db.query(query, [userID, content, timestamp], (error, result) => {
        if (error) {
            console.error("Error saving message to database:", error);
            res.status(500).send("Error saving message to database");
        } else {
            messages.push(message);
            res.send(message)
        }
    });
});

// sätt att få comments från en specifik fråga
app.get("/comments/:QuestionID", (req, res) => {
    const { QuestionID } = req.params;
    
    const query = `SELECT c.contents, c.timestamp, u.name 
                   FROM comments c 
                   JOIN users u ON c.UserID = u.userID 
                   WHERE c.QuestionID = ?`;

    db.query(query, [QuestionID], (error, results) => {
        if (error) {
            console.error("Error fetching comments:", error);
            res.status(500).send("Error fetching comments");
        } else {
            res.send(results);
        }
    });
});

// sätt att lägga till en comment till en specifik fråga
app.post("/comments", (req, res) => {
    const { QuestionID, contents } = req.body;
    

    const timestamp = new Date().toLocaleString();
    console.log(timestamp)

    const query = "INSERT INTO comments (QuestionID, userID, contents, timestamp) VALUES (?, ?, ?, ?)";
    db.query(query, [QuestionID, userID, contents, timestamp], (error, result) => {
        if (error) {
            console.error("Error saving comment to database:", error);
            res.status(500).send("Error saving comment to database");
        } else {
            res.send({ message: 'Comment lades till', comment: { contents, timestamp } });
        }
    });
});



// socket setup

io.on("connection", (socket) => {
    // user connection
    socket.on("chat", (username) => {
        activeUsers.set(username, socket); // lägg till user i uactiveUSers map
    });

    // user disconnection
    socket.on("disconnect", () => {
        activeUsers.forEach((value, key) => {
            if (value === socket) {
                activeUsers.delete(key); // ta bort user från activeUsers map
            }
        });
    });
});



// Körde på 4k här bara för att skilja mig åt
// från server.js vi tidigare kört som använder 3k
http.listen(4000, () => {
    console.log("Servern körs, besök http://localhost:4000");
});