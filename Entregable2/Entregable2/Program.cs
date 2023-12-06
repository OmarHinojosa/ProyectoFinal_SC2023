using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

class Program
{
    static void Main()
    {
        Console.WriteLine("Ingrese su número de tarjeta de crédito:");
        // Enmascarar
        string numeroTarjeta = EnmascararEntrada();

        if (numeroTarjeta.Length < 16)
        {
            Console.WriteLine("Numero de tarjeta invalido!");
        }

        // Console.WriteLine("Número de tarjeta ingresado: " + numeroTarjeta);

        // Sha256 - Hexadecimal
        string vsha256 = Obtenersha256(numeroTarjeta);

        // Console.WriteLine(vsha256);

        // Generamos una clave y un iv (Vector de Inicializacion)
        byte[] clave = Generarclave();
        byte[] iv = GenerarIV();

        // Encriptar
        string tarjetaEncriptada = EncriptarAEs(numeroTarjeta, clave, iv);

        // Console.WriteLine(tarjetaEncriptada);
        // Console.WriteLine(numeroTarjeta);

        // Desencriptar
        string tarjetaDesencriptada = DesencriptarAEs(tarjetaEncriptada, clave, iv);

        // Console.WriteLine(tarjetaDesencriptada);

        // Codificar dato Desencriptado
        string vsha256Desencr = Obtenersha256(tarjetaDesencriptada);

        if (vsha256 == vsha256Desencr)
        {
            Console.WriteLine("Proceso Finalizado de Manera Correcta");
            Console.WriteLine("Presione cualquier tecla para ver el resumen del programa:");
            Console.ReadKey();

            // Resumen
            Console.WriteLine("");
            Console.WriteLine("Numero de tarjeta ingresado: " + numeroTarjeta);
            Console.WriteLine("Valor Sha256 en Hexadecimal de la tarjeta ingresada: " + vsha256);
            Console.WriteLine("Tarjeta encriptada: " + tarjetaEncriptada);
            Console.WriteLine("Tarjeta desencriptada: " + tarjetaDesencriptada);
            Console.WriteLine("Valor Sha256 en Hexadecimal de la tarjeta desencriptada: " + vsha256Desencr);

            Console.ReadKey();
        }
        else
        {
            Console.WriteLine("Hubo algún error, no coincidio");
        }

    }

    static string EnmascararEntrada()
    {
        ConsoleKeyInfo key;
        string input = "";

        do
        {
            key = Console.ReadKey(true);

            // Verifica si la tecla presionada es un dígito y si la longitud actual no excede 16 caracteres
            if (char.IsDigit(key.KeyChar) && input.Length < 16)
            {
                input += key.KeyChar;

                if (input.Length > 4 && input.Length < 13)
                {
                    Console.Write("*"); // Muestra un asterisco en lugar del dígito ingresado
                }
                else
                {
                    Console.Write(key.KeyChar); // Muestra dígito ingresado
                }

            }
            // Verifica si la tecla presionada es la tecla de retroceso (backspace) y si hay caracteres para borrar
            else if (key.Key == ConsoleKey.Backspace && input.Length > 0)
            {
                input = input.Substring(0, input.Length - 1);
                Console.Write("\b \b"); // Borra el último carácter mostrado en la consola
            }
        }
        while (key.Key != ConsoleKey.Enter);

        Console.WriteLine(); // Salto de línea después de la entrada

        return input;
    }

    static string Obtenersha256(string input)
    {
        using (SHA256 sha256c = SHA256.Create())
        {
            // Convertir la cadena a bytes
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            // Calcular el hash SHA256
            byte[] hashByte = sha256c.ComputeHash(inputBytes);


            // string hashString = BitConverter.ToString(hashByte).Replace("-","").ToLower();

            // Console.WriteLine("Hash SHA256 de: " + input + "- " + hashString);

            //Cobvertir el Hash a formato Hexadecimal.
            StringBuilder builder = new StringBuilder();

            foreach (byte b in hashByte)
            {
                builder.Append(b.ToString("x2")); // "x2" indica el formato hexadecimal
            }

            return builder.ToString();
        }

    }

    static byte[] Generarclave()
    {
        using (AesCryptoServiceProvider aesCrip = new AesCryptoServiceProvider())
        {
            aesCrip.GenerateKey();
            return aesCrip.Key;
        }
    }

    static byte[] GenerarIV()
    {
        using (AesCryptoServiceProvider aesCrip = new AesCryptoServiceProvider())
        {
            aesCrip.GenerateIV();
            return aesCrip.IV;
        }
    }

    static string EncriptarAEs(string texto, byte[] clave, byte[] iv)
    {
        using (AesCryptoServiceProvider aesCrip = new AesCryptoServiceProvider())
        {
            aesCrip.Key = clave;
            aesCrip.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aesCrip.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] textoBytes = Encoding.UTF8.GetBytes(texto);
                    cs.Write(textoBytes, 0, textoBytes.Length);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    static string DesencriptarAEs(string textoEncriptado, byte[] clave, byte[] iv)
    {
        using (AesCryptoServiceProvider aesCrip = new AesCryptoServiceProvider())
        {
            aesCrip.Key = clave;
            aesCrip.IV = iv;

            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(textoEncriptado)))
            {
                using (CryptoStream cs = new CryptoStream(ms, aesCrip.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
