import { config } from "dotenv";
import express from "express";
import { mongoConnect } from "./db/mangoConnect";
import auth from "./routers/auth"
config()
mongoConnect().then(() => {
    const app = express()
    app.use(express.json())
    app.use("/",auth)
    app.get("/", (req, res) => res.send("Hi there"))
    const PORT = 4000
    console.info('Connected to MongoDB Atlas!');
    app.listen(PORT, () => console.log("Server running on port", PORT))
}).catch((error: any) => console.error("Unable to connect to database", error))
