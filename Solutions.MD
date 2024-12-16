Issue: Duplicate Username Error
Problem
When trying to register a new user, if the username already exists in the database, an error happens. This stops the registration.
 
Cause
The database has a rule that usernames must be unique. If a duplicate username is added, the program breaks.

 Solution
- I used a `try-except` block to catch this error.
- If the username already exists, I show a simple message to the user:  
  "Username already exists. Try another one."

Prevention
- Always check for errors when saving data to the database.
- Give the user a clear message when something goes wrong.


Issue: Missing or Broken Footballers File

Problem
The game could not pick a footballer name if the file `list_of_footballers` was missing or broken.

 Cause
The file was either not in the correct place, empty, or corrupted.

 Solution
- I added code to check for errors when reading the file:  
   
  { except Exception as e:
       print(f"[DEBUG] Error reading footballers file: {e}")
       return "unknown" }
   
- If the file is missing, the game still works by using a default word: "unknown".

Prevention
- Make sure the file `static/list_of_footballers` exists and has proper data.
- If the file is empty, log a message so the developer knows.