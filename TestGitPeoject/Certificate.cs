// -----------------------------------------------------------------------
// <copyright file="Certificate.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------

namespace SigningGitChanges
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Permissions;

    /// <summary>
    ///     X509Certificate2 implementation of ICertificate.
    /// </summary>
    [Serializable]
    public class Certificate : X509Certificate2, ICertificate
    {
        /// <summary>
        ///     id-kp-serverAuth from RFC 2459:
        ///     { iso(1) identified-organization(3) dod(6) internet(1)
        ///     security(5) mechanisms(5) pkix(7) mod(3) kp(1) }
        /// </summary>
        public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

        /// <summary>
        ///     The id to identify client authentication certificates.
        /// </summary>
        public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        ///     Identifier for smart card authentication certificates.
        /// </summary>
        public const string SmartcardAuthenticationOid = "1.3.6.1.4.1.311.20.2.2";

        /// <summary>
        ///     Identifier for MSIT-issued smart card authentication certificates.
        /// </summary>
        public const string CorporateSmartcardAuthenticationOid = "1.3.6.1.4.1.311.42.2.1";

        /// <summary>
        ///     Msit-vsmartcard-logon certificate policy identifier
        /// </summary>
        public const string VirtualSmartcardLogonOid = "1.3.6.1.4.1.311.42.1.5";

        /// <summary>
        ///     Msit-vsmartcard-Intune certificate policy identifier
        /// </summary>
        public const string VirtualSmartcardInTuneOid = "1.3.6.1.4.1.311.42.1.20";

        /// <summary>
        ///     Initializes a new instance of the Certificate class.
        /// </summary>
        /// <param name="cert">Existing X509Certificate2 instance</param>
        public Certificate(X509Certificate cert)
            : base(cert)
        {
        }

        /// <summary>
        ///     Initializes a new instance of the Certificate class.
        /// </summary>
        /// <param name="base64EncodedPublicKey">Base64 encoded string of the public key</param>
        public Certificate(string base64EncodedPublicKey)
            : base(new X509Certificate2(Convert.FromBase64String(base64EncodedPublicKey)))
        {
        }

        /// <summary>
        ///     Initializes a new instance of the Certificate class.
        /// </summary>
        /// <param name="info">Serialization information</param>
        /// <param name="context">Streaming context</param>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.InheritanceDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected Certificate(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        /// <summary>
        ///     Gets the enhanced key usage oids.
        /// </summary>
        /// <value>
        ///     The enhanced key usage oids.
        /// </value>
        public IEnumerable<Oid> EnhancedKeyUsageOids
        {
            get
            {
                return this.Extensions
                    .OfType<X509EnhancedKeyUsageExtension>()
                    .SelectMany(usage => usage.EnhancedKeyUsages.Cast<Oid>())
                    .ToList();
            }
        }

        /// <summary>
        ///     Gets the AsymmetricAlgorithm representing the certificate's public key.
        /// </summary>
        public AsymmetricAlgorithm PublicAsymmetricAlgorithm
        {
            get
            {
                // Creating a copy of this certificate so as not to return the
                // AsymmetricAlgorithms exposed by this object.  If we did not
                // do this, subsequent calls to this property would return a
                // disposed object.
                var copy = new X509Certificate2(this);
                return copy.PublicKey.Key;
            }
        }

        /// <summary>
        ///     Gets the AsymmetricAlgorithm representing the certificate's private key.
        /// </summary>
        public AsymmetricAlgorithm PrivateAsymmetricAlgorithm
        {
            get
            {
                // Creating a copy of this certificate so as not to return the
                // AsymmetricAlgorithms exposed by this object.  If we did not
                // do this, subsequent calls to this property would return a
                // disposed object.
                var copy = new X509Certificate2(this);
                return copy.PrivateKey;
            }
        }

        /// <summary>
        ///     Gets the public key in Base64 string format
        /// </summary>
        public string Base64PublicKey
        {
            get { return Convert.ToBase64String(this.Export(X509ContentType.Cert)); }
        }
    }
}