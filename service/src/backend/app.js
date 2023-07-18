const express = require("express");
var morgan = require('morgan');
const app = express();
const router = express.Router()
var sqlite3 = require("sqlite3").verbose();
var jwt = require("jsonwebtoken");
const DBSOURCE = "/service/persist/usersdb.sqlite";
const auth = require("./middleware");
const crypto = require("crypto");

const elliptic = require('elliptic');
const BN = require('bn.js');

const CURVE_A = '0';
const CURVE_B = 'cd080';
const CURVE_P = 'c00000000000000000000000000000228000000000000000000000000000018d';
const CURVE_G_X = "b044bc1fa42ca2f1d7d88e9dd22b79f0f1277b94804c1d2f7098dceaf01fc4a8";
const CURVE_G_Y = "8f2a2d6fe3550e8b6749fc4ad5fa804f941b5eedc115dd54f1b34df2b964dcf6";

const curve = new elliptic.curve.short({
  a: CURVE_A,
  b: CURVE_B,
  p: CURVE_P,
  g: [
    CURVE_G_X,
    CURVE_G_Y,
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
        salt text,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
      phone text NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
      iv text NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`, (err) => {
      if(err){
        console.log("Got error:", err);
        throw err;
      }
    })
  }
});

module.exports = db;

app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));
app.use(express.urlencoded({extended: true}));

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

router.use("/notes/:username", auth);
router.get("/notes/:username", (req, res, _) => {
  if(typeof req.params.username !== "string"){
    res.status(400).json({ error: "username must be a string" });
    return;
  }
  var sql = "SELECT u.username, u.publicKeyX, u.publicKeyY, n.note as note, n.iv as noteIv FROM notes n LEFT JOIN users u ON n.user_id=u.id WHERE u.username=?";
  db.all(sql, req.params.username, (err, rows) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.json({
      message: "success",
      data: rows,
      curve: {
        "a": CURVE_A,
        "b": CURVE_B,
        "p": CURVE_P,
        "gx": CURVE_G_X,
        "gy": CURVE_G_Y,
      },
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
    const privateKey = new BN(crypto.randomBytes(32).toString('hex'), 16);
    const privateKeyStr = privateKey.toString();
    const publicKey = curve.g.mul(privateKey);
    const publicKeyX = publicKey.getX().toString();
    const publicKeyY = publicKey.getY().toString();  
    const userid = crypto.randomUUID();
    var sql =
      "INSERT INTO users (id, username, password, privateKey, publicKeyX, publicKeyY, salt) VALUES (?,?,?,?,?,?,?)";
    var params = [
      userid,
      username,
      password,
      privateKeyStr,
      publicKeyX,
      publicKeyY,
      "",
    ];
    db.run(sql, params, function (err, _) {
      if (err) {
        console.log("Error on query ", sql, err.message);
        return res.status(400).json({ error: err.message });
      }
      const token = jwt.sign({id: userid, privateKey: privateKeyStr}, process.env.TOKEN_KEY,{expiresIn: "2h",});
      return res.status(201).json({"status": "success", "privateKey": privateKeyStr, "token":token});
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

      if ( password === rows[0].password ) {
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
