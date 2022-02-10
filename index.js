
disguised = false
const EventEmitter = require('events');
logged_in = false
staff_chat = false


const fetch = require('node-fetch');

const headers = {
	'Content-Type': 'application/json',
	Accept: 'application/json',
	'Accept-Encoding': 'gzip, deflate, br',
	Connection: 'keep-alive',
	'X-Requested-With': 'Repl.it',
	Referrer: 'https://repl.it',
	Origin: 'https://repl.it'
};

const testConfig = {
  cookie: {
    sameSite: 'None'
  }
}

class MyEmitter extends EventEmitter {}
const emitter = new MyEmitter();
const url = require("url");
const fs = require("fs");
fs.readdir("./users", (err, files) => {
  const users = files.length
});
const colors = require("colors")
const crypto = require("crypto");
const http = require("http");
const ws = require("ws");
const express = require("express");
const rateLimit = require('ws-rate-limit')(100,'10s')
const ProfanityFilter = require("bad-words");
const homepage = `${__dirname}/views/19wintersp.html`;
const testpage = `${__dirname}/views/beta.html`;
const rulespage = `${__dirname}/views/rules.html`;
const loginpage = `${__dirname}/views/login.html`;
const notfoundpage = `${__dirname}/views/404.html`;
const banpage = `${__dirname}/views/ban.html`;
const ytpage = `${__dirname}/views/youtube.html`;
const trialmod = `${__dirname}/views/trialmod.html`;
const music = `${__dirname}/music.mp3`;
const background = `${__dirname}/transparent.png`;
const imgfolder = `${__dirname}/img`;
const store = `${__dirname}/store`;
const port = 8000;
const showdown = require('showdown')
var hljs = require('highlight.js');
var marked = require('markdown-it')({
  highlight: function (str, lang) {
    if (lang && hljs.getLanguage(lang)) {
      try {
        return '<pre class="hljs" style="background-color: var(--codeblock) !important;"><code>' +
               hljs.highlight(lang, str, true).value +
               '</code></pre>';
      } catch (__) {}
    }

    return '<pre class="hljs"><code>' + marked.utils.escapeHtml(str) + '</code></pre>';
  },
  breaks: true, 
  linkify: true,
  typegrapher: true
});
console.log(marked.render("> bob"))
const JSONdb = require('simple-json-db')
const banned = new JSONdb('./banned.json') //to ban someone, put their name IN LOWERCASE in banned.json 
const youtube = JSON.parse(fs.readFileSync("./youtube.json") || "[]") || [];
const trial = JSON.parse(fs.readFileSync("./trialmod.json") || "[]") || [];
const owner = JSON.parse(fs.readFileSync("./owner.json") || "[]") || [];
const coowner = JSON.parse(fs.readFileSync("./co-owner.json") || "[]") || [];
const commands = {
	"testcommand": "alert(1)",
  "rickroll": "window.open('https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstleyVEVO')", // this will trigger the popup blocker
  "clear": "document.querySelector('#messages').innerHTML='<p><i>Chat was cleared.</i></p>'",
  "kick": "location.reload()",
  "store": "window.open ('https://store.ryangardiner1.repl.co')",
	"logout": "localStorage.settings='{}';location.reload()",
	"restart": "alert('<h1>Server restarting.</h1>', true)",
  "upvote": "pushMessage('<h1>If you like the chat, make sure to upvote!</h1>')",
  "fullscreen": "window.open('https://chat.dudeactualdev.repl.co')",
	"subscribe": "alert('Subscribe!')",
  "cmds": "window.open ('https://docs.google.com/document/d/1MpOkR720lNoSeQeVonDsnK1ahZ3QuKa6N0by1oPWwlU/edit?usp=sharing')",
  "warn": "var notify=new Notification('Repl Chat',{body:''You have been warned. The next offense will result in a ban.',icon:'https://dab1nmslvvntp.cloudfront.net/wp-content/uploads/2015/12/1450973046wordpress-errors.png'});alert('You have been warned. The next offense will result in a ban.')", //now working CROSIS PLEASE JUST TEST IT I KNOW WHAT I AM Doing --gatewayduck//ping a user ex !ping-GatewayDuckYT
  "disguise": "e",
  "undisguise": "ee",
  "ping": "var audio = new Audio('https://proxy.notificationsounds.com/notification-sounds/me-too-603/download/file-sounds-1144-me-too.mp3'); audio.play();",
  "music": "var audio = new Audio('https://chat.ryangardiner1.repl.co/music'); audio.play();",
  "msg": "test",
  "virus": "while (true) {location.reload()}"

  //Yes I have tested it BUT WHAT DID I SAY.


  //sorry i will not do it again :< also why are we talking in comments?
  
};
function playsound(
  url = "https://proxy.notificationsounds.com/notification-sounds/me-too-603/download/file-sounds-1144-me-too.mp3"
) {
  if (window.localStorage.getItem("sounds") === "true") {
    var audio = new Audio(url);
    audio.play();
  }
}
const token = process.env.TOKEN
const auth = {
	"admin": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "Admin", // <-- this will show up next to your name
		password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms", "r", "report"],
    cooldown: 1, 
    color: "red"
	},
	"trialadmin": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "Trial Mod", // <-- this will show up next to your name
		password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms", "r", "mute", "unmute", "msg", "chat", "profile", "report"],
    color: "purple",
    cooldown: 1,
    value: 4
	},
  "owner": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "Owner", // <-- this will show up next to your name
		password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms","virus","disguise","undisguise","music", "msg", "ban", "mute", "unban", "chat", "announcement", "rank", "r", "unmute", "sudo", "profile", "report", "clearlogs"],
    color: "owner-red",
    cooldown: 1,
    value: 7
	},
  "tester": {
    displayName: "Tester",
    password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e",
    availableCommands: ["msg", "ping", "r", "profile", "report"],
    cooldown: 1000,
    value: 3

  },
  "api": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "API Bot", // <-- this will show up next to your name
		password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms","virus","disguise","undisguise","music","store", "report"],
    cooldown: 1
	},
  "co-owner": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "Co-Owner", // <-- this will show up next to your name
		password: "650d39cbe88fd16f3008fc45e01ee27842ec5714f92323a85522c0e76d54736e", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms","virus","disguise","undisguise","music", "msg", "ban", "mute", "unban", "chat", "announcement", "rank", "r", "unmute", "sudo", "profile", "report", "clearlogs"],
    cooldown: 1,
    value: 6
	},
  "trialmod": { // <-- when you login, enter this as the role (THESE SHOULD BE UNIQUE)
		displayName: "Admin", // <-- this will show up next to your name
		password: "b0fa27b07fe0ec63c5c02cf946887b08f219a82ad59c77896d7df81a9fcdd297", // <-- this is the sha256 of the password
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms", "ban", "unban", "chat", "msg", "r", "mute", "unmute", "sudo", "profile", "report"],
    color: "blue",
    cooldown: 1,
    value: 5
	},
  null: {
    availableCommands: ["msg","ping", "profile", "report"],
    cooldown: 2000,
    value: 0
  },
  "null": {
    availableCommands: ["msg","ping", "profile", "report"],
    cooldown: 2000,
    value: 0
  },
  "dev": {
		displayName: "Developer",
		password: "96247a8        74f7ce8d6b4402b89a0d70b4eaa66b40b1a527df303ba8881e204aa4f",
		availableCommands: ["testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms", "report"],
    cooldown: 1
	},
  "creator": {
		displayName: "Content Creator",
		password: "bfdf54ab1cecb9d10b67d8d3f784bfa9ec9200fab7814aab2b87057429590617",
		availableCommands: ["subscribe", "msg", "r", "profile", "report"],
    cooldown: 1000,
    value: 2
	},
  "admincreator": {
		displayName: "Admin Content Creator",
		password: "f9968d401eed8043cf152e5f85aa416c7bdc26d2983340d318029609d43c9c07",
		availableCommands: ["subscribe", "testcommand", "rickroll", "clear", "kick", "logout", "restart", "upvote", "fullscreen", "warn","ping","L.ocdms", "report"],
    cooldown: 1000
	},
  "geplplus": {
    displayName: "Gepl +",
    password: "b0fa27b07fe0ec63c5c02cf946887b08f219a82ad59c77896d7df81a9fcdd297",
    availableCommands: ["msg","ping", "profile", "report"],
    cooldown: 1,
    color: "yellow",
    value: 2
  },
  "gepl": {
    displayName: "Gepl", 
    password: "b0fa27b07fe0ec63c5c02cf946887b08f219a82ad59c77896d7df81a9fcdd297",
    availableCommands: ["msg","ping", "profile", "report"],
    cooldown: 500,
    value: 1
  }
};

const app = express();
const expressDefend = require('express-defend');
const blacklist = require('express-blacklist');

const server = http.createServer(app);
app.use(blacklist.blockRequests('blacklist.txt'));
app.use(expressDefend.protect({ 
    maxAttempts: 5, 
    dropSuspiciousRequest: true,
    consoleLogging: true, 
    logFile: 'suspicious.log', 
    onMaxAttemptsReached: function(ipAddress, url){
        blacklist.addAddress(ipAddress);
        console.log(ipAddress)
    } 
}));
const wsServer = new ws.Server({ 
  server,
  verifyClient: function(info,callback) {
    console.log(info.origin)
    if (info.origin == "https://chat.dudeactualdev.repl.co" || info.origin == undefined || info.origin == "https://gepl-sync-client.lankdev.repl.co" || info.origin == "https://ade17e67-b2fa-4dc5-bbf4-7f8ff08146bd.id.replitusercontent.com" || info.origin == "https://gepl-chat.crosis.repl.co" || info.origin == "https://chat.geplcord.rf.gd") {
      callback(true);
      console.log('true');
    }
    else {
      console.log('false')
      callback(false)
    }
  }
});
const filter = new ProfanityFilter({ placeHolder: "😳️️️️️️️" });
const connections = [];
const staffon = [];
const hash = (data) => crypto.createHash("sha256").update(data).digest("hex");
const sanitize = (data) => filter.clean(data.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"));
const markfix = (data) => filter.clean(data.replace("<p>","").replace("</p>",""));
function sleep(ms) {
    return new Promise(function(resolve, reject) {
        setTimeout(function() {
            resolve()
        }, ms)
    })
}
const isProfane = (data) => filter.clean(data) == data;
const youtubeUser = (user) => [youtube.push(user.toLowerCase()), fs.writeFileSync("./youtube.json", JSON.stringify(youtube))];
const trialUser = (user) => [trial.push(user.toLowerCase()), fs.writeFileSync("./trialmod.json", JSON.stringify(trial))];
var muted = new JSONdb('./muted.json')
const banUser = (user) => user? banned.set(user.toLowerCase(), true) : null
const muteUser = (user) => muted.set(user.toLowerCase(), true)
app.engine('html',require('ejs').renderFile);
const scriptloading = `${__dirname}/views`;
app.get("/loading", (req, res) => {
  res.sendFile(`${scriptloading}/loading.html`)
})
app.get('/message', (req, res) => {
  res.sendFile(`${__dirname}/message.mp3`)
})
app.get('/arc-sw.js', (req, res) => {
  res.sendFile(`${__dirname}/arc-sw.js`)
})
app.get("/script", (req, res) => {
  res.sendFile(`${scriptloading}/script.js`)
})
app.get("/style", (req, res) => {
  res.sendFile(`${scriptloading}/script.js`)
})
app.get("/", (req, res) => {
  const cookies = req.headers.cookie ? req.headers.cookie.split(';') : null
  const user = cookies ? cookies[0].split('=')[1] : null
  const pass = cookies ? cookies[1].split('=')[1] : null
  if (user == null || pass == null) res.render(loginpage)
	else if (user && pass) {
    console.log(`eeee`)
    console.log(user)
    if (fs.existsSync(`./users/${user}.json`)) {
      console.log(`Exists`)
      var userInfo = new JSONdb(`./users/${user}.json`)
      if (userInfo.get('password') == hash(pass)) {
        res.render(homepage);
      }
    }
  } 
	else res.render(loginpage);
});
app.get("/friend", (req, res) => {
  const cookies = req.headers.cookie ? req.headers.cookie.split(';') : null
  const user = cookies ? cookies[0].split('=')[1] : null
  const pass = cookies ? cookies[1].split('=')[1] : null
  if (user == null || pass == null) res.render(loginpage)
	else if (user && pass) {
    if (fs.existsSync(`./users/${user}.json`)) {
      var userInfo = new JSONdb(`./users/${user}.json`)
      if (userInfo.get('password') == hash(pass)) {
        res.render(`${__dirname}/views/friends.html`);
      }
    }
  } 
	else res.render(loginpage);
});
app.use(express.urlencoded({ extended: true}))
app.get("/beta", (req, res) => {
  const cookies = req.headers.cookie ? req.headers.cookie.split(';') : null
  const user = cookies ? cookies[0].split('=')[1] : null
  const pass = cookies ? cookies[1].split('=')[1] : null
  if (user == null || pass == null) res.render(loginpage)
	else if (user && pass) {
    if (fs.existsSync(`./users/${user}.json`)) {
      var userInfo = new JSONdb(`./users/${user}.json`)
      if (userInfo.get('password') == hash(pass)) {
        res.render(testpage);
      }
    }
  } 
	else res.render(loginpage);
});
app.get("/music", (req, res) => {
	if (req.get("X-Replit-User-Id")) res.sendFile(music);
	else res.redirect("/login");
});
app.get("/background", (req, res) => {
	if (req.get("X-Replit-User-Id")) res.sendFile(background);
	else res.redirect("/login");
});
app.get("/login", (req, res) => {
  const cookies = req.headers.cookie ? req.headers.cookie.split(';') : null
  const username = cookies ? cookies[0].split('=')[1] : null
  const password = cookies ? cookies[1].split('=')[1] : null
  if (username && password) {
    if (fs.existsSync(`./users/${username}.json`)) {
      var userInfo = new JSONdb(`./users/${username}.json`);
      var realPass = userInfo.get('password');
      if (realPass == hash(password)) {
        console.log('password was correct')
        res.redirect('/');
      }
      else {
        res.render(loginpage);
      }
    }
    else {
      res.render(loginpage)
    }
  }
  else {
    res.render(loginpage)
  }
});
app.post("/login", (req,res) => {
  console.log(req.body.user);
  const username = decodeURIComponent(req.body.user);
  const password = decodeURIComponent(req.body.pass);
  if (fs.existsSync(`./users/${username}.json`)) {
    var userInfo = new JSONdb(`./users/${username}.json`);
    if (userInfo.get("password") == hash(password)) {
      res.cookie('GEPL_AUTH_USER', username, { httpOnly: false, path: '/'});
      res.cookie('GEPL_AUTH_PASS', password, { httpOnly: false, path: '/'});
      console.log(true)
      res.render(homepage)
    }
    else {
      console.log('failed')
    } 
  }
})
app.get("/signup", (req, res) => {
  res.render(`${__dirname}/views/signup.html`);
});
app.get(`/privacy`, (req, res) => {
  res.sendFile(`${__dirname}/views/privacypolicy.txt`)
})
app.post('/signup', (req, res) => {
  const username = req.body.user;
  const password = req.body.pass;
  console.log(username)
  var regex = /[\s~`!@#$%\^&*+=\-\[\]\\';,/{}|\\":<>\?()\._]/g;
  var regex2 = /[\s~`!@#$%\^&*+=\-\[\]\\';,/{}|\\":<>\?()\._]/g;
  if (!fs.existsSync(`./users/${username.toLowerCase()}.json`)) {
    if (!regex.test(username) && username.indexOf(' ') == -1) {
    console.log(username)
    fs.writeFileSync(`./users/${username}.json`, '')
    var userInfo = new JSONdb(`./users/${username}.json`);
    userInfo.set("password", hash(password));
    res.cookie('GEPL_AUTH_USER', username, { httpOnly: false, path: '/'});
    res.cookie('GEPL_AUTH_PASS', password, { httpOnly: false, path: '/'});
    res.redirect('/')
    }
  }
})
app.post(`/api/private/message`, (req, res) => {

  const username = req.headers["user"]
  const password = req.headers["pass"]
  const message = req.headers["message"]
  const wss = new ws(`wss://chat.dudeactualdev.repl.co?room=null`, {
    headers: {
      "user": username,
      "pass": password
    }
  });
  console.log(username);
  console.log('API SUCCESSFUL');
  wss.on('open', function open() {
    wss.send(`a${password}`)
    wss.send(`m${message}`);
    res.send(`e`)
  })
})
const atob = str => new Buffer.from(str, 'base64').toString('utf-8')

app.get("/api/public/:user/:method", (req, res) => {
  console.log('tesssssssssssstttttttt');
  console.log(req.params.user);
  const apiUser = fs.existsSync(`./users/${req.params.user}.json`) ? fs.readFileSync(`./users/${req.params.user}.json`) : JSON.stringify('This user doesnt exist');
  if (req.params.method == "ip") {
    res.send(JSON.stringify(`That is not allowed.`))
  }
  var crosisinfo = new JSONdb(`./users/Crosis.json`)
  if (!crosisinfo.get(req.params.method) || req.params.method == "all") {
    res.send(apiUser)
  }
  else {
    if (fs.existsSync(`./users/${req.params.user}.json`)) {
      var targetinfo = new JSONdb(`./users/${req.params.user}.json`);
      if (targetinfo.get(req.params.method)) {
        res.send(JSON.stringify(targetinfo.get(req.params.method)))
      }
      else res.send(JSON.stringify('Unknown method.'));
    }
    else res.send(JSON.stringify('This user does not exist.'))
  }
  console.log(req.params.method)
})

app.get("/img/:file", (req, res) =>  {
  res.sendFile(`${__dirname}/img/${req.params.file}.png`);
})
app.get("/storage/:file", (req, res) =>  {
  res.sendFile(`${__dirname}/storage/${req.params.file}.png`);
})
app.get("/ban", (req, res) => res.sendFile(banpage));
app.post("/ban", (req, res) => (hash(req.body.p) == auth.admin.password || hash(req.body.p) == auth.trialmod.password || hash(req.body.p) == auth.owner.password) ? [banUser(req.body.u),name = user, res.redirect("/")] : res.redirect("/")), connections.forEach(({ socket }) => socket.send(`j${name} was banned`));
app.get("/youtube", (req, res) => res.sendFile(ytpage));
app.post("/youtube", (req, res) => (hash(req.body.p) == auth.admin.password) ? [youtubeUser(req.body.u), res.redirect("/")] : res.redirect("/"));
app.get("/trialmod", (req, res) => res.sendFile(trialmod));
app.post("/trialmod", (req, res) => (hash(req.body.p) == auth.admin.password) ? [trialUser(req.body.u), res.redirect("/")] : res.redirect("/"));
app.all("*", (req, res) => res.sendFile(notfoundpage));
once = 0    
wsServer.on("connection", (sock, req) => {
  const cookies = req.headers.cookie ? req.headers.cookie.split(';') : null
  const newApiUser = req.headers["user"];
  const newApiPass = req.headers["pass"];
  const user1 = newApiUser ? newApiUser : cookies
  const pass1 = newApiPass ? newApiPass : cookies
  const user2 = cookies ? cookies[0].split('=')[1] : null;
  const pass2 = cookies ? cookies[1].split('=')[1] : null;
  const user = user2 ? user2 : user1
  const pass = pass2 ? pass2 : pass1
  function spam() {
		sock.send(`xGO TO https://chat.geplcord.rf.gd/login AND MAKE SURE YOU DELETE THE rf.gd COOKIE!!!!!!! YOU CAN LOG IN WITH UR SAME USERNAME, THIS IS CROSIS'S CHAT LINK BC REPL.CO IS BLOCKED.`)
	}
	setInterval(spam, 1000)
  const tokens = new JSONdb(`tokens.json`);
  function genToken(length) {
    var result           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    var charactersLength = characters.length;
    for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  var userinfo = new JSONdb(`./users/${user}.json`);
  const room1 = url.parse(req.url, true).query.friendchat ? true : null
  console.log(room1)
  const room = url.parse(req.url, true).query.room
  const friend1 = userinfo.get("recent") ? userinfo.get("recent").toLowerCase() : null;
  const friend = room1 ? url.parse(req.url, true).query.friend.toLowerCase() || "" : friend1;
  room1 ? console.log(room) : console.log('no') 
  friend1 ? console.log(friend1) : console.log(`gueguhguhg`)
  if (room1 !== null) {
  const messageHistory2 = fs.existsSync(`./dms/${friend.toLowerCase()}|${user.toLowerCase()}.txt`) ? fs.readFileSync(`./dms/${friend.toLowerCase()}|${user.toLowerCase()}.txt`).toString() : null
  const messageHistory1 = fs.existsSync(`./dms/${user.toLowerCase()}|${friend.toLowerCase()}.txt`) ? fs.readFileSync(`./dms/${user.toLowerCase()}|${friend.toLowerCase()}.txt`).toString() : messageHistory2
  const messageHistory = messageHistory1 ? messageHistory1.split(`<>`) : null

  function delay2() {
    if (messageHistory) {
      const executionTargets = user ? connections[friend].filter(({ username }) => (username == user.toLowerCase())) : connections[friend];
      executionTargets.forEach(({socket}) => socket.send(`9e`));
      for (i = 0; i < messageHistory.length; i++) {
        const executionTargets = user ? connections[friend].filter(({ username }) => (username == user.toLowerCase())) : connections[room];
        const newMessage = messageHistory[i].substring(1);
        executionTargets.forEach(({socket}) => socket.send(`h${newMessage}`))
      }
      executionTargets.forEach(({socket}) => socket.send(`se`));
    }
    else {
      console.log('failed message history')
    }
  }
  setTimeout(delay2, 1000)

  if (connections[friend] == undefined) connections[friend] = []; 
  function delay(){
    const executionTargets = user ? connections[friend].filter(({ username }) => (username == user)) : connections[friend];
    fs.readdir("./users", (err, files) => {
      var users = files.length
      connections[friend].forEach(({socket})=> socket.send(`u${users}`))
    });
    fs.readdirSync("./users").forEach(file => {
      var onlineuser = JSON.parse(fs.readFileSync(`./users/${file}`))
      var user = file.replace(".json", "")
      if (onlineuser.online == true) {
        connections[friend].forEach( ({ socket }) => socket.send(`1${user}`));
      }
      if (userinfo.get("friends")) {
        if (userinfo.get("friends").includes(`${user} `) ) {
          if (onlineuser.online == true) {
            const executionTargets = user ? connections[friend].filter(({ username }) => (username == user)) : connections[friend];
            executionTargets.forEach(({socket})=> {
              socket.send(`o ${user} true`)
            })
            executionTargets.forEach(({socket})=> {
              socket.send(`o ${user} false`)
            })
            executionTargets.forEach(({socket})=> {
              socket.send(`f ${user} true`)
            })
          }
          if (onlineuser.online == false) {
            const executionTargets = user ? connections[friend].filter(({ username }) => (username == user)) : connections[friend];
            executionTargets.forEach(({socket})=> {
              socket.send(`o ${user} true`)
            })
            executionTargets.forEach(({socket})=> {
              socket.send(`o ${user} false`)
            })
            executionTargets.forEach(({socket})=> {
              socket.send(`f ${user} false`)
            })
          }
        }
      }
    })
  }
  setTimeout(delay, 100)
  setInterval(delay,20000)
  //connections[friend].push({socket: sock, );
  function music2() {
    target = user
    const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
    executionTargets.forEach(({ socket }) => socket.send(`c${commands["music"]}`));
  }
  const name = user

  var ipBan = new JSONdb('./blacklist.json')
	if (name == null || ipBan.has(userinfo.get("ip")) || banned.has(user.toLowerCase()  )) {
    const name = user;
    const executionTargets = name ? connections[friend].filter(({ username }) => (username == name)) : connections[friend];

    
    if (1 == 2){
      connections[friend].forEach(({ socket }) => socket.send(`j${name} tried to join, but is banned :(`));
    }
    once = 1
		sock.close(1002, "Unauthorised");
	} 
  else if ( user) {
    var getData = async function(username) {
      let info = await fetch('https://staging.repl.it/graphql', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          query:
            `{userByUsername(username: "${username}") {karma, firstName, lastName, bio, isVerified, timeCreated, isLoggedIn, organization {name}, subscription {planId}, roles { name }}}`
        })
      }).then(res => res.json());
      userinfo.set("cycles", info.data.userByUsername.karma)
    };
    const name = user;

    console.log(name)
    if (fs.existsSync(`./users/${name}.json`) == false) {
      
      fs.writeFileSync(`./users/${name}.json`, '')
      var userinfo = new JSONdb(`./users/${name}.json`);
      var uids = new JSONdb(`./uids.json`)
      userinfo.set('muted', false)
      userinfo.set('level', 0)
      userinfo.set('messages', 0)
      userinfo.set('uid', uids.get("uid") + 1)
      uids.set("uid", uids.get("uid") + 1)
      if (trial.includes(name)) {
        userinfo.set('rank', 'trialmod')
        userinfo.set("staff", true)
      }
      else if (owner.includes(name)) {
        userinfo.set('rank', 'owner')
        userinfo.set("staff", true)
      }
      else {
        userinfo.set('rank', null);
      }
      getData(name)
    }
    else {
      
      var userinfo = new JSONdb(`./users/${name}.json`);
      if (!userinfo.get("level")) {
        userinfo.set("level", 0)
      }
      if (userinfo.get("notes")) {
        var notes = userinfo.get("notes")
        
      }
      if (!userinfo.get("uid")) {
        const uids = new JSONdb(`./uids.json`)
        userinfo.set('uid', uids.get("uid") + 1)
        uids.set("uid", uids.get("uid") + 1)
      }
      if (userinfo.get("rank") == null || !userinfo.get("rank")) {
        userinfo.set("staff", false)
        userinfo.set("rank",  null)
        userinfo.set("cooldown", 2000)
      } 
      else if (userinfo.get("rank") == "tester") {
        userinfo.set("staff", false)
        userinfo.set("rank",  "tester")
        userinfo.set("cooldown", 2000)
      }
      if (!userinfo.get("muted")) {
        userinfo.set("muted", false)
      }
      else {
        userinfo.set("staff", true)
        userinfo.set("cooldown", 1)
      }
      var userinfo = new JSONdb(`./users/${name}.json`)
      getData(name)
    }
    const role = userinfo.get("rank")
    console.log(role)
    function checkLevel() {
      var xmsg = userinfo.get("messages");
      if(xmsg%15==0){
        var prev = userinfo.get("level") ? userinfo.get("level") : 0;
        userinfo.set("level", prev+1);
        connections[friend].forEach(({ socket }) => socket.send(`j${name} has reached level ${prev+1}!`)); 
      };
    };
    //connections[friend].forEach(d=>console.log(d.send));
		let isAuthed = (role ? false : true), roleName = null, lastMessage = 0;
    userinfo.set("disguised", false)
		if (isAuthed) {
			connections[friend].forEach( ({ socket }) => socket.send(`j😃 ${name} joined the chat, hello!`));
      function delay() {
        connections[friend].forEach( ({ socket }) => socket.send(`jHey ${name}! If you want to see the beta, go to chat.crosis.repl.co!`));
      }
      if (userinfo.get("rank") == null) {
        connections[friend].forEach(({socket}) => socket.send(`e${name}`))
        userinfo.set("online", true)
      }
      else {
        connections[friend].forEach( ({ socket }) => socket.send(`1${name}`));
        userinfo.set("online", true)
      }
      
      if (userinfo.get("staff") == true) {
        staffon.push({ socket: sock, username: name});
        console.log('test')
      }
		}
    else {
      if (userinfo.get("rank") == null) {
        connections[friend].forEach(({socket}) => socket.send(`e${name}`))
        userinfo.set("online", true)
      }
      else {
        userinfo.set("online", true)
        connections[friend].forEach( ({ socket }) => socket.send(`1${name}`));
      }
      if (userinfo.get("staff") == true) {
        staffon.push({ socket: sock, username: name});
        console.log('test425')
      }
      connections[friend].forEach( ({ socket }) => socket.send(`j😃 ${name} joined the chat, hello!`));
      function delay() {
        connections[friend].forEach( ({ socket }) => socket.send(`jHey ${name}! If you want to see the beta, go to chat.crosis.repl.co!`));
      }
    }   
    const cooldown = auth[userinfo.get('rank')].cooldown;
    const disguised1 = userinfo.get('disguised')
    
		sock.on("message", (data) => {
      if (friend !== null && friend !== "null" && friend !== "") {
        console.log(friend)
      const role = userinfo.get("rank"),name = user, cycles = req.headers["x-replit-user-karma"]
			const command = data.toString()[0], parameter = data.toString().substring(1);
			if (!parameter || parameter.length < 1 || !room1) return;
			switch (command) {
				case "a":
				  roleName = auth[role].displayName;
					isAuthed = true;
					connections[friend].push({ socket: sock, username: user.toLowerCase() });
          connections.push({ socket: sock, username: user.toLowerCase() });
          
          console.log('authed')
          if (1==1) {
            const executionTargets = user ? connections[friend].filter(({ username }) => (username == user)) : connections[friend];
            executionTargets.forEach(({socket}) => {
              socket.send('iee')
            })
          }
					break;
        case "r":
          userinfo.set(`recent`, data.substring(1))
          console.log(data.substring(1))
          break;
        case "b":
          let ip = data.substring(1).replace('\n', '')
          userinfo.set("ip", hash(ip))
          if (user == "gatewayDuckYT") {
            console.log(ip)
          }
          console.log(hash(ip))
          break;
        case "i":
          const executionTargets = user ? connections[friend].filter(({ username }) => (username == user)) : connections[friend];
          executionTargets.forEach(({socket}) => socket.send(`l`))
          break;
        case "t":
          if (userinfo.get("disguised") == false || userinfo.has("disguised") == false)  {connections[friend].forEach(({ socket }) => socket.send(`t${name}`))}
          if (userinfo.get("disguised") == true) {connections[friend].forEach(({ socket }) => socket.send(`t${disguise1}`))}
          break;
				case "m": 
					const messageTime = new Date();
					if (isAuthed) {  
						if ((messageTime.getTime() - lastMessage) > cooldown) {
              console.log(userinfo.get("cooldown"))
              console.log(messageTime.getTime() - lastMessage)
              console.log(lastMessage)
							if (parameter.startsWith("/")) {
								const cmd = parameter.includes(" ") ? parameter.substring(1, parameter.indexOf(" ")).toLowerCase() : parameter.substring(1).toLowerCase();
								if (!commands[cmd] && cmd !== "msg" && cmd !== "whisper" && cmd !== "ban" && cmd !== "mute" && cmd !== "unban" && cmd !== "chat" && cmd !== "friend" && cmd !== "rank" && cmd !== "unmute" && cmd !== "r" && cmd !== "sudo" && cmd !== "warn" && cmd !== "target" && cmd !== "profile" && cmd != "report" && cmd !== "clearlogs") {
									sock.send("xNot a command");
									return;
								}
								if (!auth[role]) {
									sock.send("xAuthorisation error");
									return;
								}
								if (auth[role].availableCommands.includes(cmd)) {
									const target = parameter.includes(" ") ? parameter.split(" ")[1] : null;
                  var userinfo2 = new JSONdb(`./users/${target}.json`)
                  const self = user
                  const msg1 = parameter.includes(" ") ? parameter.substring(0,parameter.indexOf(" ") + 2 + target.length) : null;
                  const msg = parameter.replace(msg1,"")
                  
                  const target3 = parameter.substring(0);
                  const target2 = target3.replace("/r ", "");
                  const target4 = target3.replace("/profile ", "");
                  console.log(target2);
									if (commands[cmd] && cmd !== "disguise" && cmd !== "undisguise" && cmd !== "msg" && cmd !== "ban" && cmd !== "mute" && cmd !== "unban" && cmd !== "chat" && cmd !== "friend" && cmd !== "rank" && cmd !== "unmute" && cmd !== "r" && cmd !== "sudo" && cmd !== "warn" && cmd !== "profile" && cmd !== "report" && cmd !== "clearlogs") {
										const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
										executionTargets.forEach(({ socket }) => socket.send(`c${commands[cmd]}`));
                    break;
									} 
                  else if (cmd == "ban") {
										const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
                    if (msg == "-s") {
                      banUser(target)
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was banned by ${name}`)})
                      executionTargets.forEach(({socket}) => socket.close())
                      break;
                    }
                    if (msg == "-s ip") {
                      var targetinfo = new JSONdb(`./users/${target}.json`)
                      ipBan.set(targetinfo.get("ip"), true);
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was banned by ${name}`)})
                      executionTargets.forEach(({socket}) => socket.close())
                      break;
                    }
                    else {
                      banUser(target);
                      connections[friend].forEach(({socket})=> {socket.send(`j${target} was banned by ${name}`)})
                      executionTargets.forEach(({socket}) => socket.close())
                      break;
                    }
                    
                  }
                  else if (cmd == "clearlogs") {
                    fs.writeFileSync(`logs.txt`, '', (error) => {
                      console.log(error);
                    })
                  }
                  else if (cmd == "unban") {
                    const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend]; 
                    connections[friend].forEach(({socket})=> {socket.send(`j${target} was unbanned by ${name}`)})
                    executionTargets.forEach(({socket}) => socket.close())
                    banned.delete(target.toLowerCase())
                    var targetinfo = new JSONdb(`./users/${target}.json`)
                    ipBan.delete(targetinfo.get("ip"))
                    break;
                  }
                  else if (cmd == "warn") {
                    console.log('test123');
                    const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
                    executionTargets.forEach(({socket}) => socket.send(`xYou have been warned for ${msg}. Next offense will be a ban.`))
                    return;
                  }
									else if (cmd == "disguise") {
										disguise1 = target
								    userinfo.set("disguised", true)
									}
                  else if (cmd == "chat") {
                    if (userinfo.get("staffchat") == false) {
                      userinfo.set("staffchat", true)
                    }
                    else {
                      userinfo.set("staffchat", false)
                    }
                  }
                  else if (cmd == "friend") {
                    if (fs.existsSync(`./users/${target}.json`) && userinfo.get("friends") && userinfo.get("friends").includes(target) == false) {
                      if (userinfo.get("friends")) {
                        userinfo.set("friends",  `${target} ` + userinfo.get("friends"))
                      }
                    }
                    else if (fs.existsSync(`./users/${target}.json`) && !userinfo.get("friends")) {
                      userinfo.set("friends", `${target} ` )
                    }
                  }
                  else if (cmd == "rank") {
                    const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
                    executionTargets.forEach(({socket}) => socket.send(`d${msg}`))
                  }
                  else if (cmd == "r") {
                    if (userinfo.get("recent")) {
                      var respond = userinfo.get("recent")
                      var targetinfo = new JSONdb(`./users/${respond}.json`)
                      const executionTargets = respond ? connections[friend].filter(({ username }) => (username == respond)) : connections[friend];
                      const selfTargets = self ? connections[friend].filter(({ username }) => (username == self)) : connections[friend];
                      const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} From- <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(target2)))}`;
                      executionTargets.forEach(({ socket }) => socket.send(message));
                      console.log(executionTargets)
                      lastMessage = messageTime.getTime();
                      console.log('worked')
                      selfTargets.forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} To- <strong><code>${sanitize(respond)}</code></strong>: ${markfix(marked.render(sanitize(target2)))}`))
                      executionTargets.forEach(({socket}) => socket.send(`b${name}`))
                    }
                    

                  }
                  else if (cmd == "profile") {
                    if (target4.length < 500) {
                      userinfo.set("description", target4);
                      console.log('test')
                    }
                    else {
                      console.log('faileddddd')
                    }
                  }
                  else if (cmd == "mute") {
                    if (msg == "-s") {
                      muteUser(target)
                      console.log(muted.get(target))
                      const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was muted by ${name}`)})
                      executionTargets.forEach(({socket}) => socket.close()) 
                    }
                    else {
                      muteUser(target)
                      console.log(muted.get(target))
                      const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
                      executionTargets.forEach(({socket}) => socket.close()) 
                      connections[friend].forEach(({socket})=> {socket.send(`j${target} was muted by ${name}`)})
                    }
                  }
                  else if (cmd == "unmute") {
                    if (msg == "-s") {
                      muted.delete(target.toLowerCase())
                      const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend]; 
                      executionTargets.forEach(({socket}) => socket.close())
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was unmuted by ${name}`)})
                    }
                    else {
                      muted.delete(target.toLowerCase())
                      const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend]; 
                      executionTargets.forEach(({socket}) => socket.close())
                      connections[friend].forEach(({socket})=> {socket.send(`j${target} was unmuted by ${name}`)})
                    }
                  }
                  else if (cmd == "sudo") {
                    if (fs.existsSync(`./users/${target}.json`)) {
                      console.log('test')
                      console.log(target)
                      console.log(msg)
                      var fakeRoleName = auth[userinfo2.get("rank")].displayName
                      var userinfo2 = new JSONdb(`./users/${target}.json`)
                      connections[friend].forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> (${userinfo2.get("cycles")}) ${fakeRoleName  ? `<a href="javascript:alert('Verified as ${fakeRoleName}')">[${fakeRoleName}]</a>` : ""} <strong><code>${sanitize(target)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`))
                    }
                    else console.log('test')
                  }
                  else if (cmd == "report") {
                    if (fs.existsSync(`./users/${target}.json`)) {
                      const executionTargets = name ? connections[friend].filter(({ username }) => (username == name)) : connections[friend];
                      staffon.forEach(({socket}) => socket.send(`m${target} was reported by ${name} for ${marked.render(msg)}`))
                      executionTargets.forEach(({socket}) => socket.send(`mSuccessfully reported ${target} for ${msg}`))
                    }
                  }
                  else if (cmd == "msg" && msg !== null  && target !== null && !muted.get(name) || cmd == "whisper" && msg !== null) {
                    var targetinfo = new JSONdb(`./users/${target}.json`)
										const executionTargets = target ? connections[friend].filter(({ username }) => (username == target)) : connections[friend];
										const selfTargets = self ? connections[friend].filter(({ username }) => (username == self)) : connections[friend];
                    const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} From- <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`;
                    executionTargets.forEach(({socket}) => socket.send(`b${name}`))
                    executionTargets.forEach(({ socket }) => socket.send(message));
                    console.log(executionTargets)
                    lastMessage = messageTime.getTime();
                    console.log('worked')
                    selfTargets.forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} To- <strong><code>${sanitize(target)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`))
                    userinfo.set("recent", target)
                  }
									if (cmd == "undisguise" && userinfo.get("disguised") == true) {
								    userinfo.set("disguised", false)
										connections[friend].forEach(({ socket }) => socket.send(`x${disguise1}`));
									} else sock.send("xNot a command");
                  
                } 
                else sock.send("xYou can't use that command");} 
                else if (userinfo.get("disguised") == true) {
                  console.log("worked")
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `` : ""} <strong>${disguise1}</strong>: ${markfix(marked.render(parameter))}`;
                  connections[friend].forEach(({ socket }) => socket.send(message));
                  lastMessage = messageTime.getTime();
                  connections[friend].forEach(({ socket }) => socket.send(`e${disguise1}`));
                }
                else if (userinfo.get("staff") == true && userinfo.get("staffchat") == true){
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> (Staff Chat) ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(parameter)))}`;
                  staffon.forEach(({ socket }) => socket.send(message));
                }
                else {
                  function highlight(message) {
                    let pingusers = message.match(/@\b([A-Za-z0-9]+)\b/g);
                    if (pingusers === null || message.includes('https://' || 'repl.it')) {return message}
                    for (i = 0; i < pingusers.length; i++) {
                      let pinguser = pingusers[i].substring(1);
                      if (fs.existsSync(`./users/${pinguser}.json`)) {
                      var userinfo = new JSONdb(`./users/${pinguser}.json`)
                      if (userinfo.get('online') == true && !muted.get(user.toLowerCase())) {
                      message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                      const executionTargets = pinguser ? connections[friend].filter(({ username }) => (username == pinguser)) : connections[friend];
                      executionTargets.forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                      }
                      }
                      else if (pinguser == "everyone" || pinguser == "all") {
                        if (!muted.get(user.toLowerCase())) {
                        message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                        connections[friend].forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                        }
                      }
                    }
                    return message;
                  }
                    function color(message) {
                      if (auth[role].color == "default" || auth[role].color == null ) {
                        console.log(name)
                        return message;
                      } 
                      else {
                        message = `<span class=${auth[role].color}>${message}</span>`
                        return message;
                      }
                    }
                    const message = `m(${userinfo.get("level")}) ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <div class = "tooltip" onclick = "switchUser('${user.toLowerCase()}')"><strong><code>${userinfo.get("nickname") ? userinfo.get("nickname") : sanitize(user)}</code></strong><span title = "test" class = "tooltiptext">(@${user})</span></div>: ${markfix(highlight(color((marked.render(parameter)))))}`;
                    lastMessage = messageTime.getTime();
                    if (!muted.get(user.toLowerCase()) && friend !== undefined && friend !== null && friend !== "" && friend !== "null") {
                      userinfo.set("recent", friend);
                      const executionTargets = connections.filter(({username})=> (username == friend.toLowerCase()))
                      executionTargets.forEach(({ socket }) => socket.send(message)) 
                      const self = connections.filter(({username})=> (username == user.toLowerCase()))
                      self.forEach(({ socket }) => socket.send(message))
                      if (fs.existsSync(`./dms/${user.toLowerCase()}|${friend.toLowerCase()}.txt`) && friend !== undefined && room !== null ) {
                        fs.appendFileSync(`./dms/${user.toLowerCase()}|${friend.toLowerCase()}.txt`, `${message}<>`, (error) => {
                          console.log(error)
                        })
                      }
                      else {
                        if (friend !== undefined && friend !== null) {
                          console.log(message)
                          fs.appendFileSync(`./dms/${friend.toLowerCase()}|${user.toLowerCase()}.txt`, `${message}<>`, (error) => {
                            console.log(error)
                          })
                        }

                      }

                    } 
                    else if (friend == "" || friend == "null" || friend == null || friend == undefined) {
                      const self = connections[room].filter(({username})=> (username == user.toLowerCase()))
                      self.forEach(({socket}) => socket.send(`xPlease put the users name again by clicking the green circle.`))
                    }
                    else {
                      console.log(message)
                      const self = connections[friend].filter(({username})=> (username == user))
                      self.forEach(({ socket }) => socket.send(message))
                    lastMessage = messageTime.getTime();
                  }
                  userinfo.set('messages', userinfo.get('messages') + 1)
                  checkLevel();
                  getData(name)
                  lastMessage = messageTime.getTime();
                  console.log(`The time taken was ${lastMessage}`)
                  break;
                }
						} else sock.send("xYou are sending messages too fast, please slow down");
          
					}
					break;
				default:
					sock.send("xInvalid command");
					break;
        break;
			}
      }
		});
		sock.on("close", (code) => {
      const messageTime = new Date();
      if ((messageTime.getTime() - lastMessage) > cooldown) {
        connections[friend].forEach(({ socket }) => socket.send(`j😔 ${name} left the chat, goodbye...`));
        userinfo.set("online", false)
        lastMessage = messageTime.getTime();
      } 
      connections[friend].forEach(({ socket }) => socket.send(`2${name}`));
		});
  }
  }
  else if (!room1) {
  console.log(room)
  console.log(user)
  const messageHistory1 = fs.readFileSync('logs.txt').toString()
  const messageHistory = messageHistory1.split(`<>`)
  const announcementHistory1 = fs.readFileSync(`announcements.txt`).toString()
  const aHistory = announcementHistory1.split(`<>`)
  function delay3() {
    if (aHistory) {
      for (i = 0; i < aHistory.length; i++) {
        const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
        const newA = aHistory[i];
        executionTargets.forEach(({socket}) => socket.send(`f${newA}`))
      }
    }
  }
  setTimeout(delay3, 3000)
  function delay2() {
    if (messageHistory) {
      for (i = 0; i < messageHistory.length; i++) {
        const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
        const newMessage = messageHistory[i].substring(1)
        executionTargets.forEach(({socket}) => socket.send(`h${newMessage}`))
      }
      const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
      executionTargets.forEach(({socket}) => socket.send(`se`))
    }
    else {
      console.log('failed message history')
    }
  }
  setTimeout(delay2, 2000)

  if (connections[room] == undefined) connections[room] = []; 
  function delay(){
    const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
    fs.readdir("./users", (err, files) => {
      var users = files.length
      connections[room].forEach(({socket})=> socket.send(`u${users}`))
    });
    fs.readdirSync("./users").forEach(file => {
      var onlineuser = JSON.parse(fs.readFileSync(`./users/${file}`))
      var user = file.replace(".json", "")
      if (onlineuser.online == true) {
        connections[room].forEach( ({ socket }) => socket.send(`1${user}`));
      }
    })
  }
  setTimeout(delay, 2000)
  //connections[room].push({socket: sock, );
  function music2() {
    target = user
    const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
    executionTargets.forEach(({ socket }) => socket.send(`c${commands["music"]}`));
  }
  const name = user

  var ipBan = new JSONdb('./blacklist.json')
  console.log(user)
  if (user == null) {
    console.log(`gwegniegniewr`)
  }
	if ( !user || ipBan.has(userinfo.get("ip")) || user == null || user && user !== null ? banned.has(user.toLowerCase()) : null ) {
    const name = user;
    const executionTargets = name ? connections[room].filter(({ username }) => (username == name)) : connections[room];

    
    if (1 == 2){
      connections[room].forEach(({ socket }) => socket.send(`j${name} tried to join, but is banned :(`));
    }
    once = 1
		sock.close(1002, "Unauthorised");
	} 
  else if ( userinfo.get("password") !== hash(pass) ) {
    const executionTargets = name ? connections[room].filter(({ username }) => (username == name)) : connections[room];
    executionTargets.forEach(({socket}) => socket.send(`xWrong password, don't try to change cookies :|`))
  }
  else if ( user) {
    var getData = async function(username) {
      let info = await fetch('https://staging.repl.it/graphql', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          query:
            `{userByUsername(username: "${username}") {karma, firstName, lastName, bio, isVerified, timeCreated, isLoggedIn, organization {name}, subscription {planId}, roles { name }}}`
        })
      }).then(res => res.json());
      return info.data.userByUsername.karma
    };
    const name = user;

    console.log(name)
    if (fs.existsSync(`./users/${name}.json`) == false) {
      
      fs.writeFileSync(`./users/${name}.json`, '')
      var userinfo = new JSONdb(`./users/${name}.json`);
      var uids = new JSONdb(`./uids.json`)
      userinfo.set('muted', false)
      userinfo.set('level', 0)
      userinfo.set('messages', 0)
      userinfo.set('uid', uids.get("uid") + 1)
      uids.set("uid", uids.get("uid") + 1)
      if (trial.includes(name)) {
        userinfo.set('rank', 'trialmod')
        userinfo.set("staff", true)
      }
      else if (owner.includes(name)) {
        userinfo.set('rank', 'owner')
        userinfo.set("staff", true)
      }
      else {
        userinfo.set('rank', null);
      }
    }
    else {
      
      var userinfo = new JSONdb(`./users/${name}.json`);
      if (!userinfo.get("level")) {
        userinfo.set("level", 0)
      }
      if (userinfo.get("notes")) {
        var notes = userinfo.get("notes")
        
      }
      if (!userinfo.get("uid")) {
        const uids = new JSONdb(`./uids.json`)
        userinfo.set('uid', uids.get("uid") + 1)
        uids.set("uid", uids.get("uid") + 1)
      }
      if (userinfo.get("rank") == null || !userinfo.get("rank")) {
        userinfo.set("staff", false)
        userinfo.set("rank",  null)
        userinfo.set("cooldown", 2000)
      } 
      else if (userinfo.get("rank") == "tester") {
        userinfo.set("staff", false)
        userinfo.set("rank",  "tester")
        userinfo.set("cooldown", 2000)
      }
      if (!userinfo.get("muted")) {
        userinfo.set("muted", false)
      }
      else {
        userinfo.set("staff", true)
        userinfo.set("cooldown", 1)
      }
      var userinfo = new JSONdb(`./users/${name}.json`)
    }
    const role = userinfo.get("rank")
    console.log(role)
    function checkLevel() {
      var xmsg = userinfo.get("messages");
      if(xmsg%15==0){
        var prev = userinfo.get("level") ? userinfo.get("level") : 0;
        userinfo.set("level", prev+1);
        connections[room].forEach(({ socket }) => socket.send(`j${name} has reached level ${prev+1}!`)); 
      };
    };
    //connections[room].forEach(d=>console.log(d.send));
		let isAuthed = (role ? false : true), roleName = null, lastMessage = 0;
    userinfo.set("disguised", false)
		if (isAuthed) {
      if (!newApiUser) {
        connections[room].forEach( ({ socket }) => socket.send(`j😃 ${name} joined the chat, hello!`));
      }
      function delay() {
        connections[room].forEach( ({ socket }) => socket.send(`jHey ${name}! If you want to see the beta, go to chat.crosis.repl.co!`));
      }
      if (userinfo.get("rank") == null) {
        connections[room].forEach(({socket}) => socket.send(`e${name}`))
        userinfo.set("online", true)
      }
      else {
        connections[room].forEach( ({ socket }) => socket.send(`1${name}`));
        userinfo.set("online", true)
      }
      
      if (userinfo.get("staff") == true) {
        staffon.push({ socket: sock, username: name});
        console.log('test')
      }
		}
    else {
      if (userinfo.get("rank") == null) {
        connections[room].forEach(({socket}) => socket.send(`e${name}`))
        userinfo.set("online", true)
      }
      else {
        userinfo.set("online", true)
        connections[room].forEach( ({ socket }) => socket.send(`1${name}`));
      }
      if (userinfo.get("staff") == true) {
        staffon.push({ socket: sock, username: name});
        console.log('test425')
      }
      if (!newApiUser) {
        connections[room].forEach( ({ socket }) => socket.send(`j😃 ${name} joined the chat, hello!`));
      }
      function delay() {
        connections[room].forEach( ({ socket }) => socket.send(`jHey ${name}! If you want to see the beta, go to chat.crosis.repl.co!`));
      }
    }   
    const cooldown = auth[userinfo.get('rank')].cooldown;
    const disguised1 = userinfo.get('disguised')
    
		sock.on("message", (data) => {
      const role = userinfo.get("rank"),name = user, cycles = req.headers["x-replit-user-karma"]
			const command = data.toString()[0], parameter = data.toString().substring(1);
			if (!parameter || parameter.length < 1) return;
			switch (command) {
        case "z": 
          userinfo.set("rank", parameter);
          if (parameter == "null") userinfo.set("rank", null);
          break;
        case "g":
          var executionTargets3 = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
          connections[room].forEach(({socket}) => socket.send(`g${user}`));
          break;
        case "e": 
          const imguids = new JSONdb(`imgids.json`)
          imguids.set("id", imguids.get("id") + 1)
          let base64Image = parameter.split(';base64,').pop();
          fs.writeFileSync(`./storage/${imguids.get("id")}.png`, base64Image, {encoding: 'base64'});
          var executionTargets2 = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
          console.log('testtttttttt')
          executionTargets2.forEach(({socket}) => socket.send(`khttps://chat.dudeactualdev.repl.co/storage/${imguids.get("id")}`))
          break;
				case "a":
				  roleName = auth[role].displayName;
					isAuthed = true;
					connections[room].push({ socket: sock, username: user });
          console.log('authed')
          if (1==1) {
            const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
            executionTargets.forEach(({socket}) => {
              socket.send('iee')
            })
          }
					break;
        case "r":
          userinfo.set(`recent`, data.substring(1))
          console.log(data.substring(1))
          break;
        case "b":
          let ip = data.substring(1).replace('\n', '')
          userinfo.set("ip", hash(ip))
          console.log(hash(ip))
          break;
        case "i":
          const executionTargets = user ? connections[room].filter(({ username }) => (username == user)) : connections[room];
          executionTargets.forEach(({socket}) => socket.send(`l`))
          break;
        case "t":
          if (userinfo.get("disguised") == false) connections[room].forEach(({ socket }) => socket.send(`t${name}`))
          if (userinfo.get("disguised") == true) connections[room].forEach(({ socket }) => socket.send(`t${disguise1}`))
          break;
				case "m": 
					const messageTime = new Date();
					if (isAuthed) {  
						if ((messageTime.getTime() - lastMessage) > cooldown) {
              console.log(userinfo.get("cooldown"))
              console.log(messageTime.getTime() - lastMessage)
              console.log(lastMessage)
							if (parameter.startsWith("/")) {
								const cmd = parameter.includes(" ") ? parameter.substring(1, parameter.indexOf(" ")).toLowerCase() : parameter.substring(1).toLowerCase();
								if (!commands[cmd] && cmd !== "msg" && cmd !== "whisper" && cmd !== "ban" && cmd !== "mute" && cmd !== "unban" && cmd !== "chat" && cmd !== "announcement" && cmd !== "rank" && cmd !== "unmute" && cmd !== "r" && cmd !== "sudo" && cmd !== "warn" && cmd !== "target" && cmd !== "profile" && cmd != "report" && cmd !== "clearlogs") {
									sock.send("xNot a command");
									return;
								}
								if (!auth[role]) {
									sock.send("xAuthorisation error");
									return;
								}
								if (auth[role].availableCommands.includes(cmd)) {
									const target = parameter.includes(" ") ? parameter.split(" ")[1] : null;
                  var userinfo2 = new JSONdb(`./users/${target}.json`)
                  const self = user
                  const msg1 = parameter.includes(" ") ? parameter.substring(0,parameter.indexOf(" ") + 2 + target.length) : null;
                  const msg = parameter.replace(msg1,"")
                  
                  const target3 = parameter.substring(0);
                  const target2 = target3.replace("/r ", "");
                  const target5 = target3.replace("/announcement ", "");
                  const target4 = target3.replace("/profile ", "");
                  console.log(target2);
									const targetvalue = new JSONdb(`./users/${target}.json`)
									if (commands[cmd] && cmd !== "disguise" && cmd !== "undisguise" && cmd !== "msg" && cmd !== "ban" && cmd !== "mute" && cmd !== "unban" && cmd !== "chat" && cmd !== "announcement" && cmd !== "rank" && cmd !== "unmute" && cmd !== "r" && cmd !== "sudo" && cmd !== "warn" && cmd !== "profile" && cmd !== "report" && cmd !== "clearlogs") {
										const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
										executionTargets.forEach(({ socket }) => socket.send(`c${commands[cmd]}`));
                    break;
									} 
                  else if (cmd == "ban") {
										const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
                    if (auth[userinfo.get("rank")].value > auth[targetvalue.get("rank")].value) {
                      if (msg == "-s") {
                        banUser(target)
                        staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was banned by ${name}`)})
                        executionTargets.forEach(({socket}) => socket.close())
                        break;
                      }
                      if (msg == "-s ip") {
                        var targetinfo = new JSONdb(`./users/${target}.json`)
                        ipBan.set(targetinfo.get("ip"), true);
                        staffon.forEach(({socket})=> { socket.send(`j(Staff Chat) - ${target} was banned by ${name}`)})
                        executionTargets.forEach(({socket}) => socket.close())
                        break;
                      }
                      else {
                        banUser(target);
                        connections[room].forEach(({socket})=> {socket.send(`j${target} was banned by ${name}`)})
                        executionTargets.forEach(({socket}) => socket.close())
                        break;
                      }       
                    }

                    
                  }
                  else if (cmd == "clearlogs") {
                    fs.writeFileSync(`logs.txt`, '', (error) => {
                      console.log(error);
                    })
                  }
                  else if (cmd == "unban") {
                    const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room]; 
                    connections[room].forEach(({socket})=> {socket.send(`j${target} was unbanned by ${name}`)})
                    executionTargets.forEach(({socket}) => socket.close())
                    if (target) {
                      banned.delete(target.toLowerCase())
                    }
                    
                    var targetinfo = new JSONdb(`./users/${target}.json`)
                    ipBan.delete(targetinfo.get("ip"))
                    break;
                  }
                  else if (cmd == "warn") {
                    console.log('test123');
                    const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
                    executionTargets.forEach(({socket}) => socket.send(`xYou have been warned for ${msg}. Next offense will be a ban.`))
                    return;
                  }
									else if (cmd == "disguise") {
										disguise1 = target
								    userinfo.set("disguised", true)
									}
                  else if (cmd == "chat") {
                    if (userinfo.get("staffchat") == false) {
                      userinfo.set("staffchat", true)
                    }
                    else {
                      userinfo.set("staffchat", false)
                    }
                  }
                  else if (cmd == "announcement") {
                    connections[room].forEach(({socket}) => socket.send(`f<h3>${name}: ${target5}</h3><br />`))
                    fs.appendFileSync(`announcements.txt`, `<><h3>${name}: ${marked.render(target5)}</h3><br />`)
                  }
                  else if (cmd == "rank") {
                    const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
                    executionTargets.forEach(({socket}) => socket.send(`d${msg}`))
                  }
                  else if (cmd == "r") {
                    if (userinfo.get("recent")) {
                      var respond = userinfo.get("recent")
                      var targetinfo = new JSONdb(`./users/${respond}.json`)
                      const executionTargets = respond ? connections[room].filter(({ username }) => (username == respond)) : connections[room];
                      const selfTargets = self ? connections[room].filter(({ username }) => (username == self)) : connections[room];
                      const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} From- <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(target2)))}`;
                      executionTargets.forEach(({ socket }) => socket.send(message));
                      console.log(executionTargets)
                      lastMessage = messageTime.getTime();
                      console.log('worked')
                      selfTargets.forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} To- <strong><code>${sanitize(respond)}</code></strong>: ${markfix(marked.render(sanitize(target2)))}`))
                      executionTargets.forEach(({socket}) => socket.send(`b${name}`))
                    }
                    

                  }
                  else if (cmd == "profile") {
                    if (target4.length < 500) {
                      userinfo.set("description", target4);
                      console.log('test')
                    }
                    else {
                      console.log('faileddddd')
                    }
                  }
                  else if (cmd == "mute") {
                    if (auth[userinfo.get("rank")].value > auth[targetvalue.get("rank")].value) {
                    if (msg == "-s") {
                      muteUser(target)
                      console.log(muted.get(target))
                      const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was muted by ${name}`)})
                      executionTargets.forEach(({socket}) => socket.close()) 
                    }
                    else {
                      muteUser(target)
                      console.log(muted.get(target))
                      const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
                      executionTargets.forEach(({socket}) => socket.close()) 
                      connections[room].forEach(({socket})=> {socket.send(`j${target} was muted by ${name}`)})
                    }
                    }
                  }
                  else if (cmd == "unmute") {
                    if (msg == "-s") {
                      muted.delete(target.toLowerCase())
                      const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room]; 
                      executionTargets.forEach(({socket}) => socket.close())
                      staffon.forEach(({socket})=> {socket.send(`j(Staff Chat) - ${target} was unmuted by ${name}`)})
                    }
                    else {
                      muted.delete(target.toLowerCase())
                      const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room]; 
                      executionTargets.forEach(({socket}) => socket.close())
                      connections[room].forEach(({socket})=> {socket.send(`j${target} was unmuted by ${name}`)})
                    }
                  }
                  else if (cmd == "sudo") {
                    if (fs.existsSync(`./users/${target}.json`)) {
                  function highlight(message) {
                    let pingusers = message.match(/@\b([A-Za-z0-9]+)\b/g);
                    if (pingusers === null || message.includes('https://' || 'repl.it')) {return message}
                    for (i = 0; i < pingusers.length; i++) {
                      let pinguser = pingusers[i].substring(1);
                      if (fs.existsSync(`./users/${pinguser}.json`)) {
                      var userinfo = new JSONdb(`./users/${pinguser}.json`)
                      if (userinfo.get('online') == true && !muted.get(user.toLowerCase())) {
                      message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                      const executionTargets = pinguser ? connections[room].filter(({ username }) => (username == pinguser)) : connections[room];
                      executionTargets.forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                      }
                      }
                      else if (pinguser == "everyone" || pinguser == "all") {
                        if (!muted.get(user.toLowerCase())) {
                        message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                        connections[room].forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                        }
                      }
                    }
                    return message;
                  }
                    function color(message) {
                      if (auth[role].color == "default" || auth[role].color == null ) {
                        console.log(name)
                        return message;
                      } 
                      else {
                        message = `<span class=${auth[role].color}>${message}</span>`
                        return message;
                      }
                    }
                      console.log('test')
                      console.log(target)
                      console.log(msg)
                      var fakeRoleName = auth[userinfo2.get("rank")].displayName
                      var userinfo2 = new JSONdb(`./users/${target}.json`)
                      connections[room].forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> (${userinfo2.get("level")}) ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <div class = "tooltip"><strong><code>${userinfo2.get("nickname") ? userinfo2.get("nickname") : sanitize(target)}</code></strong><span title = "test" class = "tooltiptext">(@${target})</span></div>: ${markfix(highlight(color((marked.render(msg)))))}`))
                    }
                    else console.log('test')
                  }
                  else if (cmd == "report") {
                    if (fs.existsSync(`./users/${target}.json`)) {
                      const executionTargets = name ? connections[room].filter(({ username }) => (username == name)) : connections[room];
                      staffon.forEach(({socket}) => socket.send(`m${target} was reported by ${name} for ${marked.render(msg)}`))
                      executionTargets.forEach(({socket}) => socket.send(`mSuccessfully reported ${target} for ${msg}`))
                    }
                  }
                  else if (cmd == "msg" && msg !== null  && target !== null && !muted.get(name) || cmd == "whisper" && msg !== null) {
                    var targetinfo = new JSONdb(`./users/${target}.json`)
										const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
										const selfTargets = self ? connections[room].filter(({ username }) => (username == self)) : connections[room];
                    const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} From- <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`;
                    executionTargets.forEach(({socket}) => socket.send(`b${name}`))
                    executionTargets.forEach(({ socket }) => socket.send(message));
                    console.log(executionTargets)
                    lastMessage = messageTime.getTime();
                    console.log('worked')
                    selfTargets.forEach(({socket}) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} To- <strong><code>${sanitize(target)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`))
                    userinfo.set("recent", target)
                  }
									if (cmd == "undisguise" && userinfo.get("disguised") == true) {
								    userinfo.set("disguised", false)
										connections[room].forEach(({ socket }) => socket.send(`x${disguise1}`));
									} else sock.send("xNot a command");
                  
                } 
                else sock.send("xYou can't use that command");} 
                else if (userinfo.get("disguised") == true) {
                  console.log("worked")
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `` : ""} <strong>${disguise1}</strong>: ${markfix(marked.render(parameter))}`;
                  connections[room].forEach(({ socket }) => socket.send(message));
                  lastMessage = messageTime.getTime();
                  connections[room].forEach(({ socket }) => socket.send(`e${disguise1}`));
                }
                else if (userinfo.get("staff") == true && userinfo.get("staffchat") == true){
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> (Staff Chat) ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(parameter)))}`;
                  staffon.forEach(({ socket }) => socket.send(message));
                }
                else {
                  function highlight(message) {
                    let pingusers = message.match(/@\b([A-Za-z0-9]+)\b/g);
                    if (pingusers === null || message.includes('https://' || 'repl.it')) {return message}
                    for (i = 0; i < pingusers.length; i++) {
                      let pinguser = pingusers[i].substring(1);
                      if (fs.existsSync(`./users/${pinguser}.json`)) {
                      var userinfo = new JSONdb(`./users/${pinguser}.json`)
                      if (userinfo.get('online') == true && !muted.get(user.toLowerCase())) {
                      message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                      const executionTargets = pinguser ? connections[room].filter(({ username }) => (username == pinguser)) : connections[room];
                      executionTargets.forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                      }
                      }
                      else if (pinguser == "everyone" || pinguser == "all") {
                        if (!muted.get(user.toLowerCase())) {
                        message = message.replace(pingusers[i], `<span class="ping-color">@${pinguser}</span>`);
                        connections[room].forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
                        }
                      }
                    }
                    return message;
                  }
                    function color(message) {
                      if (auth[role].color == "default" || auth[role].color == null ) {
                        console.log(name)
                        return message;
                      } 
                      else {
                        message = `<span class=${auth[role].color}>${message}</span>`
                        return message;
                      }
                    }
                    const message = `m<i>@${messageTime.toLocaleTimeString()}</i> (${userinfo.get("level")}) ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <div class = "tooltip"><strong><code>${userinfo.get("nickname") ? userinfo.get("nickname") : sanitize(name)}</code></strong><span title = "test" class = "tooltiptext">(@${name})</span></div>: ${markfix(highlight(color((marked.render(parameter)))))}`;
                    connections[room].forEach( ({ socket }) => socket.send(`1${user}`));
                    lastMessage = messageTime.getTime();
                    if (!muted.has(user.toLowerCase())) {  
                      if (!newApiUser) {
                        connections[room].forEach(({ socket }) => socket.send(message))
                        console.log(`NOOOOOOOOOOOO`) 
                      }
                      if (newApiUser) {
                        connections[room].forEach(({ socket }) => socket.send(message)) 
                        console.log('fjwniwebgubwegubeg')
                      }

                      
                      fs.appendFileSync('logs.txt', `<>${message}`, (error) => {
                        console.log(error)
                      })
                    } 
                    else {
                      console.log(message)
                      const self = connections[room].filter(({username})=> (username == user))
                      self.forEach(({ socket }) => socket.send(message))
                    lastMessage = messageTime.getTime();
                  }
                  userinfo.set('messages', userinfo.get('messages') + 1)
                  checkLevel();
                  lastMessage = messageTime.getTime();
                  console.log(`The time taken was ${lastMessage}`)
                  break;
                }
						} else sock.send("xYou are sending messages too fast, please slow down");
          
					}
					break;
				default:
					sock.send("xInvalid command");
					break;
        break;
			}
		});
		sock.on("close", (code) => {
      const messageTime = new Date();
      if ((messageTime.getTime() - lastMessage) > cooldown) {
        connections[room].forEach(({ socket }) => socket.send(`j😔 ${name} left the chat, goodbye...`));
        userinfo.set("online", false)
        lastMessage = messageTime.getTime();
      } 
      connections[room].forEach(({ socket }) => socket.send(`2${name}`));
		});
  }
  else  {
    const cooldown = 1
    const role = "api", name = "API Bot";
    //connections[room].forEach(d=>console.log(d.send));
		let isAuthed = (role ? false : true), roleName = null, lastMessage = 0;
		if (isAuthed) {
			connections[room].forEach( ({ socket }) => socket.send(`j😃 ${name} joined the chat, hello!`));
			connections[room].push({ socket: sock, username: name });
		}
		sock.on("message", (data) => {
      const role = "api",name = "API Bot",cycles = req.headers["x-replit-user-karma"]
			const command = data.toString()[0], parameter = data.toString().substring(1);
			if (!parameter || parameter.length < 1) return;
			switch (command) {
				case "a":
				  roleName = auth["api"].displayName;
					isAuthed = true;
					connections[room].push({ socket: sock, username: name });
					break;
        case "p":
          if (hash(parameter) == "2151390df5202e26dc4a13b3d45e716af58162f7bf182507d55a8f8f3e376adb") {
            hidden = true
            function delay() {
              hidden = false
              logged_in = true
              
            }
            setTimeout(delay,50)
          }
        case "t":
          connections[room].forEach(({ socket }) => socket.send(`t${name}`))
          break;
        case "l":  
          logged_in = false
				case "m":
          if (logged_in == true && hidden == false) {
            console.log('worked')
            const messageTime = new Date();
            if (isAuthed) {
              if ((messageTime.getTime() - lastMessage) > cooldown) {
                if (parameter.startsWith("/")) {
                  const cmd = parameter.includes(" ") ? parameter.substring(1, parameter.indexOf(" ")).toLowerCase() : parameter.substring(1).toLowerCase();
                  if (!commands[cmd]) {
                    sock.send("xNot a command");
                    return;
                  }
                  if (!auth[role]) {
                    sock.send("xAuthorisation error");
                    return;
                  }
                  if (auth[role].availableCommands.includes(cmd)) {
									const target = parameter.includes(" ") ? parameter.split(" ")[1] : connections[room];
                  const self = user
                  const msg1 = parameter.includes(" ") ? parameter.substring(0,parameter.indexOf(" ") + 2 + target.length) : null;
                  const msg = parameter.replace(msg1,"")
                  console.log(msg)
									if (commands[cmd] && cmd !== "disguise" && cmd !== "undisguise" && cmd !== "msg" ) {
										const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
										executionTargets.forEach(({ socket }) => socket.send(`c${commands[cmd]}`));
									} 
									if (cmd == "disguise") {
										disguise1 = target
								    disguised1 = true
									}
                  if (cmd == "msg" && msg !== null || cmd == "whisper" && msg !== null) {
										const executionTargets = target ? connections[room].filter(({ username }) => (username == target)) : connections[room];
										const selfTargets = self ? connections[room].filter(({ username }) => (username == self)) : connections[room];
                    console.log(executionTargets)
                    const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} From- <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(msg)))}`;
                    executionTargets.forEach(({ socket }) => socket.send(message));
                    console.log(executionTargets)
                    lastMessage = messageTime.getTime();
                    console.log('worked')
                    } else sock.send("xNot a command");
                    
                  } 
                  else sock.send("xYou can't use that command");} 
                else if (parameter.includes("@") && (messageTime.getTime() - lastMessage) > cooldown) {
                  const pinguser = parameter.includes("") ? parameter.split("@")[1] : null;
									const executionTargets = pinguser ? connections[room].filter(({ username }) => (username == pinguser)) : connections[room];
									executionTargets.forEach(({ socket }) => socket.send(`c${commands["ping"]}`));
									connections[room].forEach(({ socket }) => socket.send(`m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <strong>${sanitize(name)}</strong>: ${markfix(marked.render(sanitize(parameter.substring(0))))}`)); 
								  lastMessage = messageTime.getTime();
								  connections[room].forEach(({ socket }) => socket.send(`e${name}`));
                } else {
                  if (disguised1 == true) {
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `` : ""} <strong>${disguise1}</strong>: ${markfix(marked.render(parameter))}`;
                  connections[room].forEach(({ socket }) => socket.send(message));
                  lastMessage = messageTime.getTime();
                  connections[room].forEach(({ socket }) => socket.send(`e${disguise1}`));
                  }
                  else {
                  const message = `m<i>@${messageTime.toLocaleTimeString()}</i> ${roleName ? `<a href="javascript:alert('Verified as ${roleName}')">[${roleName}]</a>` : ""} <strong><code>${sanitize(name)}</code></strong>: ${markfix(marked.render(sanitize(parameter)))}`;
                  connections[room].forEach(({ socket }) => socket.send(message));
                  lastMessage = messageTime.getTime();
                  connections[room].forEach(({ socket }) => socket.send(`e${name}`));
                  }
                }
              } else sock.send("xYou are sending messages too fast, please slow down");
            
            }
          }
					break;
				default:
					sock.send("xInvalid command");
					break;
			}
		});
		sock.on("close", (code) => {
      const messageTime = new Date();
      if ((messageTime.getTime() - lastMessage) > cooldown) {
        connections[room].forEach(({ socket }) => socket.send(`x${name}`));
        connections[room].forEach(({ socket }) => socket.send(`j😔 ${name} left the chat, goodbye...`));
        lastMessage = messageTime.getTime();
        logged_in = false
      } 
		});
  }
  }

});

server.listen(port, () => console.log(`Listening on port ${port}.`));



  
