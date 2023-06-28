const express = require("express");
const app = express();
const router = express.Router()
var sqlite3 = require("sqlite3").verbose();
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const DBSOURCE = "/service/persist/usersdb.sqlite";
const auth = require("./middleware");
const crypto = require("crypto");
var morgan = require('morgan')

const elliptic = require('elliptic');
const BN = require('bn.js');

const curve = new elliptic.curve.short({
  a: '0',
  b: 'cd080',
  p: 'c00000000000000000000000000000228000000000000000000000000000018d',
  g: [
    "b044bc1fa42ca2f1d7d88e9dd22b79f0f1277b94804c1d2f7098dceaf01fc4a8",
    "8f2a2d6fe3550e8b6749fc4ad5fa804f941b5eedc115dd54f1b34df2b964dcf6",
  ]
})

const port = 3004;
require("dotenv").config();

let db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error(err.message);
    throw err;
  } else {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id text PRIMARY KEY,
        username text NOT NULL UNIQUE,
        password text,
        privateKey text,
        publicKeyX text,
        publicKeyY text,
        salt text
      );`,
      (err) => {
        if(err){
          console.log("Got error:", err);
          throw err;
        }
      }
    );
    db.run(`CREATE TABLE IF NOT EXISTS phones (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id text,
      phone text NOT NULL
    );`, (err) => {
      if(err){
        console.log("Got error:", err);
        throw err;
      }
    });
    db.run(`CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id text,
      note text NOT NULL,
      iv text NOT NULL
    );`, (err) => {
      if(err){
        console.log("Got error:", err);
        throw err;
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
  if(typeof req.params.username !== "string"){
    res.status(400).json({ error: "username must be a string" });
    return;
  }
  var sql = "SELECT u.username, GROUP_CONCAT(p.phone) as phones FROM users u LEFT JOIN phones p ON p.user_id=u.id WHERE u.username = ? GROUP BY u.username";
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

router.use("/notes", auth);
router.get("/notes", (req, res, _) => {
  var sql = "SELECT u.username, u.publicKeyX, u.publicKeyY, n.note as note, n.iv as noteIv FROM notes n LEFT JOIN users u ON n.user_id=u.id";
  db.all(sql, (err, rows) => {
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

    if ( !username || typeof username !== "string" ) {
      errors.push("username is missing");
    }
    if ( !password || typeof password !== "string" ) {
      errors.push("password is missing");
    }
    if ( username.length < 3 || username.length > 30 ) {
      errors.push("username must be between 3 and 30 characters");
    }
    if ( password.length < 3 || password.length > 30 ) {
      errors.push("password must be between 3 and 30 characters");
    }
    if (errors.length) {
      return res.status(400).json({ error: errors.join(",") });
    }

    var sql = "SELECT * FROM users WHERE username = ?";
    await db.all(sql, username, (err, result) => {
      if (err) {
        console.log("Error on query ", sql, err.message);
        return res.status(402).json({ error: err.message });
      }

      if (result.length === 0) {
        var salt = bcrypt.genSaltSync(10);
        const privateKey = new BN(crypto.randomBytes(32).toString('hex'), 16);
        const publicKey = curve.g.mul(privateKey);
        const publicKeyX = publicKey.getX().toString();
        const publicKeyY = publicKey.getY().toString();  
        var sql =
          "INSERT INTO users (id, username, password, privateKey, publicKeyX, publicKeyY, salt) VALUES (?,?,?,?,?,?,?)";
        var params = [
          crypto.randomUUID(),
          username,
          bcrypt.hashSync(password, salt),
          privateKey.toString(),
          publicKeyX,
          publicKeyY,
          salt,
        ];
        db.run(sql, params, function (err, _) {
          if (err) {
            console.log("Error on query ", sql, err.message);
            return res.status(400).json({ error: err.message });
          }
          return res.status(201).json({"status": "success", "privateKey": privateKey.toString()});
        });
      } else {
        return res.status(404).json({"status": "error", "message": "User Already Exist. Please Login"});
      }
    });
  } catch (err) {
    return res.status(400).json({"status": "error", "message":err.message});
  }
});

router.use("/addphone", auth);
router.post("/addphone", async (req, res) => {
  var errors = [];
  try {
    const { phone } = req.body;

    if (!phone || typeof phone !== "string") {
      errors.push("phone is missing");
    }

    if (phone.length < 3 || phone.length > 200) {
      errors.push("phone must be between 3 and 200 characters");
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
    return res.status(400).json({"status": "error", "message":err.message});
  }
});

router.use("/addnote", auth);
router.post("/addnote", async (req, res) => {
  var errors = [];
  try {
    const { note } = req.body;

    if (!note || typeof note !== "string") {
      errors.push("note is missing");
    }

    if (note.length < 3 || note.length > 200) {
      errors.push("note must be between 3 and 200 characters");
    }

    if (errors.length) {
      return res.status(400).json({ error: errors.join(",") });
    }

    const key = crypto
      .createHash('sha512')
      .update(req.user.privateKey)
      .digest('hex')
      .substring(0, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    encryptedNote = Buffer.from(cipher.update(note, 'utf8', 'hex') + cipher.final('hex')).toString('base64')

    var params = [
      req.user.id,
      encryptedNote,
      iv.toString('base64'),
    ];
    db.run("INSERT INTO notes (user_id, note, iv) VALUES (?,?,?)", params, function (err, _) {
      if (err) {
        return res.status(450).json({ error: err.message });
      }
    });
    return res.status(201).json({"status": "success"});
  } catch (err) {
    return res.status(400).json({"status": "error", "message":err.message});
  }
});


router.use("/profile", auth);
router.get("/profile", async (req, res) => {
  var sql = "SELECT u.username, u.privateKey, GROUP_CONCAT(p.phone) as phones FROM users u LEFT JOIN phones p ON p.user_id=u.id WHERE u.id = ? GROUP BY u.id";
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
    if (!(username && password) || typeof username !== "string" || typeof password !== "string") {
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
        const token = jwt.sign({id: rows[0].id, privateKey: rows[0].privateKey}, process.env.TOKEN_KEY,{expiresIn: "2h",});
        return res.status(200).json({"token": token});
      } else {
        return res.status(400).json({"status":"error","message":"no Match"});
      }
    });
  } catch (err) {
    return res.status(400).json({"status": "error", "message":err.message});
  }
});

app.listen(port, () => console.log(`API listening on port ${port}!`));
