import mongoose from 'mongoose';
import { config } from "dotenv";
config()

const connectionString = `mongodb+srv://fitness-db:${process.env.DB_PASSWORD}@fitness.t5d1rn2.mongodb.net/?retryWrites=true&w=majority`
export const mongoConnect = async () => {
    await mongoose.connect(connectionString)
}

