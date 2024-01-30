import { object, string, number, date, InferType } from 'yup';
export const userAuthSchema = object({
    email: string().email().max(256).required("An email is required"),
    password: string().min(8).max(128).required("A password is required").matches(
        /(?=.*[a-z])(?=.*[A-Z])((?=.*\d)|(?=.*[@#$%^&-+=()!? "])).{8,128}$/,
        "Your password must have 8 characters, 1 uppercase letter, 1 lowercase letter, and 1 special character or 1 number."
    )
}) 
