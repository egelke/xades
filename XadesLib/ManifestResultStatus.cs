using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IM.Xades
{
    /// <summary>
    /// Indicates the outcome of the manifest validation.
    /// </summary>
    public enum ManifestResultStatus
    {
        /// <summary>
        /// The manifest reference is valid.
        /// </summary>
        Valid,

        /// <summary>
        /// The manifest reference is invalid.
        /// </summary>
        Invalid
    }
}
