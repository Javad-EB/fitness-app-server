import express from "express";
const app = express()
app.use(express.json())
app.get("/", (req, res) => res.send("Hi there"))
const PORT = 4000
app.listen(PORT, () => console.log("Listening on Port", PORT))
