const express = require("express");
const app = express();
const router = express.Router()
var sqlite3 = require("sqlite3").verbose();
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const DBSOURCE = "usersdb.sqlite";
const auth = require("./middleware");
const crypto = require("crypto");
var morgan = require('morgan')

const port = 3004;
require("dotenv").config();

let db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error(err.message);
    throw err;
  } else {
    var user1_id = crypto.randomUUID();
    var user2_id = crypto.randomUUID();
    db.run(
      `CREATE TABLE users (
        id text PRIMARY KEY,
        username text NOT NULL UNIQUE,
        password text,
        salt text
      );`,
      (err) => {
        if (!err) {
          var insert = "INSERT INTO users (id, username, password, salt) VALUES (?,?,?,?)";
          var salt = bcrypt.genSaltSync(10);
          db.run(insert, [
            user1_id,
            "user1",
            bcrypt.hashSync("user1", salt),
            salt
          ]);

          var salt = bcrypt.genSaltSync(10);
          db.run(insert, [
            user2_id,
            "user2",
            bcrypt.hashSync("user2", salt),
            salt
          ]);
        }
      }
    );
    db.run(`CREATE TABLE phones (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id text,
      phone text NOT NULL
    );`, (err) => {
      if(!err){
        var insert = "INSERT INTO phones (user_id, phone) VALUES (?,?)";
        db.run(insert, [
          user1_id,
          "ENOflag1",
        ]);
        db.run(insert, [
          user2_id,
          "ENOflag2"
        ]);
      }
    })
  }
});

module.exports = db;

app.use(express.urlencoded({extended: true}));
app.use(morgan('combined'));

app.use('/', router)

router.get("/", (_, res) => res.send("WORKING"));

router.use("/user/:username", auth);
router.get("/user/:username", (req, res, _) => {
  var sql = "SELECT u.username, u.salt, GROUP_CONCAT(p.phone) as phones FROM users u LEFT JOIN phones p ON p.user_id=u.id WHERE u.username = ? GROUP BY u.username";
  db.all(sql, req.params.username, (err, rows) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.json({
      message: "success",
      data: rows,
    });
  });
});

router.post("/register", async (req, res) => {
  var errors = [];
  try {
    const { username, password } = req.body;

    if (!username) {
      errors.push("username is missing");
    }
    if (!password) {
      errors.push("password is missing");
    }

    if (errors.length) {
      return res.status(400).json({ error: errors.join(",") });
    }

    var sql = "SELECT * FROM users WHERE username = ?";
    await db.all(sql, username, (err, result) => {
      if (err) {
        return res.status(402).json({ error: err.message });
      }

      if (result.length === 0) {
        var salt = bcrypt.genSaltSync(10);
        var sql =
          "INSERT INTO users (id, username, password, salt) VALUES (?,?,?,?)";
        var params = [
          crypto.randomUUID(),
          username,
          password,
          salt,
        ];
        db.run(sql, params, function (err, _) {
          if (err) {
            return res.status(400).json({ error: err.message });
          }
        });
      } else {
        return res.status(404).json({"status": "error", "message": "User Already Exist. Please Login"});
      }
    });
    return res.status(201).json({"status": "success"});
  } catch (err) {
    console.log("ALOOOO", err)
    return res.status(400).json({"status": "error", "message":err});
  }
});

router.use("/addphone", auth);
router.post("/addphone", async (req, res) => {
  var errors = [];
  try {
    const { phone } = req.body;

    if (!phone) {
      errors.push("phone is missing");
    }

    if (errors.length) {
      return res.status(400).json({ error: errors.join(",") });
    }
    var params = [
      req.user.id,
      phone
    ];
    db.run("INSERT INTO phones (user_id, phone) VALUES (?,?)", params, function (err, _) {
      if (err) {
        return res.status(450).json({ error: err.message });
      }
    });
    return res.status(201).json({"status": "success"});
  } catch (err) {
    console.log(err);
    return res.status(400).json({"status": "error", "message":err});
  }
});

router.use("/profile", auth);
router.get("/profile", async (req, res) => {
  var sql = "SELECT u.username, GROUP_CONCAT(p.phone) as phones FROM users u LEFT JOIN phones p ON p.user_id=u.id WHERE u.id = ? GROUP BY u.id";
  db.all(sql, req.user.id, (err, rows) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    return res.json({
      message: "success",
      data: rows,
    });
  });
});

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!(username && password)) {
      return res.status(400).json({"status":"error","message":"input username and password"});
    }
    var sql = "SELECT * FROM users WHERE username = ?";
    db.all(sql, username, function (err, rows) {
      if ( err ) {
        return res.status(400).json({"status":"error","message": err.message });
      }

      if ( rows.length != 1 ){
        return res.status(400).json({"status":"error","message": "no user found" });
      }
      var PHash = bcrypt.hashSync(password, rows[0].salt);

      if ( PHash === rows[0].password ) {
        const token = jwt.sign({id: rows[0].id}, process.env.TOKEN_KEY,{expiresIn: "2h",});
        return res.status(200).json({"token": token});
      } else {
        return res.status(400).json({"status":"error","message":"no Match"});
      }
    });
  } catch (err) {
    return res.status(400).json({"status": "error", "message":err});
  }
});

app.listen(port, () => console.log(`API listening on port ${port}!`));
