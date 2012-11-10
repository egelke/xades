using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IM.Xades
{
    /// <summary>
    /// Different types of XAdES.
    /// </summary>
    /// <remarks>
    /// All current froms are defined, this does not mean the library supports all.
    /// </remarks>
    [Flags]
    public enum XadesForm
    {
        /// <summary>
        /// Basic Electronic Signature: basic form just satisfying Directive legal requirements for advanced signature.
        /// </summary>
        XadesBes,
        /// <summary>
        /// Explicit Policy based Electronic Signature: XAdES-BES with a mandatory signature policy (e.g. for a legal/contractual context).
        /// </summary>
        XadesEpes,
        /// <summary>
        /// Timestamp: adding timestamp field to protect against repudiation.
        /// </summary>
        XadesT,
        /// <summary>
        /// Complete: adding references to verification data (certificates and revocation lists) to the signed documents to allow off-line verification and verification in future (but does not store the actual data).
        /// </summary>
        XadesC,
        /// <summary>
        /// Extended: adding timestamps on the references introduced by XAdES-C to protect against possible compromise of certificates in chain in future.
        /// </summary>
        XadesX,
        /// <summary>
        /// Extended long-term: adding actual certificates and revocation lists to the signed document to allow verification in future even if their original source is not available.
        /// </summary>
        XadesXL,
        /// <summary>
        /// Archival: adding possibility for periodical timestamping (e.g. each year) of the archived document to prevent compromise caused by weakening signature during long-time storage period.
        /// </summary>
        XadesA
    }
}
