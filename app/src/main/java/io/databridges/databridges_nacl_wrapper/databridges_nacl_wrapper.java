/*
    DataBridges Java for Android NaCl wrapper for databridges library.
    https://www.databridges.io/


    Copyright 2022 Optomate Technologies Private Limited.

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package io.databridges.databridges_nacl_wrapper;

import static io.databridges.databridges_nacl_wrapper.TweetNacl.randombytes;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import io.databridges.databridges_nacl_wrapper.TweetNacl;

public class databridges_nacl_wrapper {
    public String secret="";

    public databridges_nacl_wrapper(){
        this.secret = "";
    }

    public String write(String message) throws dbnwError
    {
        if (this.secret.isEmpty()){
            throw new dbnwError("INVALID_SECRET" , "");
        }

        if(message.isEmpty()){
            throw new dbnwError("INVALID_DATA" , "");
        }
        try {
            TweetNacl.SecretBox sbox = new TweetNacl.SecretBox(this.secret.getBytes(StandardCharsets.UTF_8));
            byte[] nonce = new byte[24];
            randombytes(nonce, 24);
            byte[] cipher = sbox.box(message.getBytes(StandardCharsets.UTF_8), nonce);
            String snonce = Base64.encodeToString(nonce, Base64.DEFAULT).replace("\n", "");
            String scipher =  Base64.encodeToString(cipher, Base64.DEFAULT).replace("\n", "");
            return snonce + ":" + scipher;
        } catch (Exception e) {
            throw new dbnwError("NACL_EXCEPTION" , e.getMessage());
        }
    }

    public String read(String message) throws dbnwError{
        if (this.secret.isEmpty()){
            throw new dbnwError("INVALID_SECRET" , "");
        }

        if(message.isEmpty()){
            throw new dbnwError("INVALID_DATA" , "");
        }

        if(!message.contains(":")){
            throw new dbnwError("INVALID_DATA" , "");
        }
        String[] split = message.split(":");
        if(split.length != 2){
            throw new dbnwError("INVALID_DATA" , "");
        }

        try {
            TweetNacl.SecretBox sbox = new TweetNacl.SecretBox(this.secret.getBytes(StandardCharsets.UTF_8));

            byte[] nonce = Base64.decode(split[0], Base64.DEFAULT);
            byte[] bmessage = Base64.decode(split[1], Base64.DEFAULT);
            String cmessage = new String(sbox.open(bmessage, nonce), StandardCharsets.UTF_8);
            return cmessage;
        }catch (Exception e)
        {
            throw new dbnwError("NACL_EXCEPTION" , e.getMessage());
        }
    }

}

