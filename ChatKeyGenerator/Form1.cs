using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security;
using System.Security.Cryptography;

namespace ChatKeyGenerator
{
    public partial class Form1 : Form
    {
        string mePublic = "";
        ECDiffieHellmanCng me = new ECDiffieHellmanCng();
        byte[] salt;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(textBox1.Text) || textBox1.Text.Length != 8)
                {
                    MessageBox.Show("Invalid One-Time-Password!", "NFKeygen", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                string[] data = textBox2.Text.Split('|');
                byte[] partnerSalt = Convert.FromBase64String(data[0]);
                CngKey k = CngKey.Import(Convert.FromBase64String(data[1]), CngKeyBlobFormat.EccPublicBlob);
                byte[] sharedKey = me.DeriveKeyMaterial(k);
                byte[] combinedSalt = new byte[salt.Length];
                string priv = Convert.ToBase64String(sharedKey);
                sharedKey = null;
                
                for(int i = 0; i < salt.Length; i++)
                {
                    combinedSalt[i] = (byte)(salt[i] ^ partnerSalt[i]);
                }

                Rfc2898DeriveBytes k2 = new Rfc2898DeriveBytes(textBox1.Text + priv, combinedSalt, 100000);
                
                Clipboard.SetText(Convert.ToBase64String(k2.GetBytes(32)));
                MessageBox.Show("Key copied to clipboard!");
                Close();
            }
            catch
            {
                MessageBox.Show("Invalid partner key!", "NFKeygen", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            MessageBox.Show(me.KeySize.ToString());
            foreach(var k in me.LegalKeySizes)
            {
                MessageBox.Show(k.MinSize.ToString());
            }
            byte[] random = new byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetNonZeroBytes(random);
            salt = random;
            me.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            me.HashAlgorithm = CngAlgorithm.Sha512;
            mePublic = Convert.ToBase64String(random) + "|" + Convert.ToBase64String(me.PublicKey.ToByteArray());
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(mePublic);
            button2.Text = "Key copied!";
            timer1.Start();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            button2.Text = "Copy my public key";
            timer1.Stop();
        }
    }
}
