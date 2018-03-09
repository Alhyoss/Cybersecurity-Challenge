1. We have to send http requests of the form "/address/..." where the "..." part encode the string "gimme the second flag ..."
2. By analyzing the previous requests, you will find out that the hexadecimal part (the "..." part) of the request is exactly 6 times longer than the decoded base64 string in the answer.
3. By messing around with the hexadecimal value, you will find out that 6 hexadecimal character in the http request actually encodes one character of the decoded base 64 string of the answer
4. Knowing that, you can now write "gimme the second flag ..." with the corresponding hexadecimal string simply by copy pasting the corresponding character in the other requests.

For example, if the request "/address/aabbcc112233" we get bacj the string "me", you know that the character "m" is encoded with "aabbcc" in the url
