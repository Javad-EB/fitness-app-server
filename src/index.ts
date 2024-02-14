import { config } from "dotenv";
import express from "express";
import { mongoConnect } from "./db/mangoConnect";
import cors from "cors";
import router from "./routers/index";

config()
mongoConnect().then(() => {
    const app = express()
    app.use(express.json())
    app.use(cors())
    app.use("/api/v1", router)
    const PORT = 4000
    console.info('Connected to MongoDB Atlas!');
    app.listen(PORT, () => console.log("Server running on port", PORT))
}).catch((error: any) => console.error("Unable to connect to database", error))
