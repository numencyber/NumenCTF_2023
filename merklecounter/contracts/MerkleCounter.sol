// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @dev These functions deal with verification of Merkle Tree proofs.
 *
 * The tree and the proofs can be generated using our
 * https://github.com/OpenZeppelin/merkle-tree[JavaScript library].
 * You will find a quickstart guide in the readme.
 *
 * WARNING: You should avoid using leaf values that are 64 bytes long prior to
 * hashing, or use a hash function other than keccak256 for hashing leaves.
 * This is because the concatenation of a sorted pair of internal nodes in
 * the merkle tree could be reinterpreted as a leaf value.
 * OpenZeppelin's JavaScript library generates merkle trees that are safe
 * against this attack out of the box.
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    /**
     * @dev Calldata version of {verify}
     *
     * _Available since v4.7._
     */
    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProofCalldata(proof, leaf) == root;
    }

    /**
     * @dev Returns the rebuilt hash obtained by traversing a Merkle tree up
     * from `leaf` using `proof`. A `proof` is valid if and only if the rebuilt
     * hash matches the root of the tree. When processing the proof, the pairs
     * of leafs & pre-images are assumed to be sorted.
     *
     * _Available since v4.4._
     */
    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Calldata version of {processProof}
     *
     * _Available since v4.7._
     */
    function processProofCalldata(bytes32[] calldata proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    /**
     * @dev Returns true if the `leaves` can be simultaneously proven to be a part of a merkle tree defined by
     * `root`, according to `proof` and `proofFlags` as described in {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerify(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProof(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Calldata version of {multiProofVerify}
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function multiProofVerifyCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32 root,
        bytes32[] memory leaves
    ) internal pure returns (bool) {
        return processMultiProofCalldata(proof, proofFlags, leaves) == root;
    }

    /**
     * @dev Returns the root of a tree reconstructed from `leaves` and sibling nodes in `proof`. The reconstruction
     * proceeds by incrementally reconstructing all inner nodes by combining a leaf/inner node with either another
     * leaf/inner node or a proof sibling node, depending on whether each `proofFlags` item is true or false
     * respectively.
     *
     * CAUTION: Not all merkle trees admit multiproofs. To use multiproofs, it is sufficient to ensure that: 1) the tree
     * is complete (but not necessarily perfect), 2) the leaves to be proven are in the opposite order they are in the
     * tree (i.e., as seen from right to left starting at the deepest layer and continuing at the next layer).
     *
     * _Available since v4.7._
     */
    function processMultiProof(
        bytes32[] memory proof,
        bool[] memory proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    /**
     * @dev Calldata version of {processMultiProof}.
     *
     * CAUTION: Not all merkle trees admit multiproofs. See {processMultiProof} for details.
     *
     * _Available since v4.7._
     */
    function processMultiProofCalldata(
        bytes32[] calldata proof,
        bool[] calldata proofFlags,
        bytes32[] memory leaves
    ) internal pure returns (bytes32 merkleRoot) {
        // This function rebuilds the root hash by traversing the tree up from the leaves. The root is rebuilt by
        // consuming and producing values on a queue. The queue starts with the `leaves` array, then goes onto the
        // `hashes` array. At the end of the process, the last hash in the `hashes` array should contain the root of
        // the merkle tree.
        uint256 leavesLen = leaves.length;
        uint256 totalHashes = proofFlags.length;

        // Check proof validity.
        require(leavesLen + proof.length - 1 == totalHashes, "MerkleProof: invalid multiproof");

        // The xxxPos values are "pointers" to the next value to consume in each array. All accesses are done using
        // `xxx[xxxPos++]`, which return the current value and increment the pointer, thus mimicking a queue's "pop".
        bytes32[] memory hashes = new bytes32[](totalHashes);
        uint256 leafPos = 0;
        uint256 hashPos = 0;
        uint256 proofPos = 0;
        // At each step, we compute the next hash using two values:
        // - a value from the "main queue". If not all leaves have been consumed, we get the next leaf, otherwise we
        //   get the next hash.
        // - depending on the flag, either another value from the "main queue" (merging branches) or an element from the
        //   `proof` array.
        for (uint256 i = 0; i < totalHashes; i++) {
            bytes32 a = leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++];
            bytes32 b = proofFlags[i]
                ? (leafPos < leavesLen ? leaves[leafPos++] : hashes[hashPos++])
                : proof[proofPos++];
            hashes[i] = _hashPair(a, b);
        }

        if (totalHashes > 0) {
            unchecked {
                return hashes[totalHashes - 1];
            }
        } else if (leavesLen > 0) {
            return leaves[0];
        } else {
            return proof[0];
        }
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}

contract MerkleCounter {
    bytes32 private root=hex"139dbeaa356c79aaa48d4ea57d05243da57fef0ffa76b2fc5729faf0f00e096f";
    mapping(string => string) public verified;
    event log_string(string x);
    bool public flag;
    function verify(bytes32[] memory proof,string memory k,string memory v) public {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(k, v))));
        require(bytes(verified[k]).length<1,"Already verified");
        require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
        verified[k]=v;
        flag = true;
        emit log_string("success");
    }

    function isSolved() public view returns(bool) {
        return flag;
    }

    constructor() {
        verified["39191"]="83928";
        verified["13993"]="13202";
        verified["03476"]="37156";
        verified["17734"]="98544";
        verified["09612"]="03558";
        verified["14300"]="01638";
        verified["25883"]="61681";
        verified["38761"]="72046";
        verified["20357"]="76631";
        verified["22826"]="85217";
        verified["03726"]="02804";
        verified["35709"]="90964";
        verified["23205"]="77208";
        verified["38442"]="07618";
        verified["11535"]="44189";
        verified["23675"]="23780";
        verified["37902"]="64162";
        verified["28237"]="96473";
        verified["39892"]="29558";
        verified["15070"]="16534";
        verified["42473"]="17102";
        verified["15102"]="85211";
        verified["32896"]="29985";
        verified["20815"]="00415";
        verified["32649"]="28730";
        verified["27708"]="22462";
        verified["30674"]="36720";
        verified["01278"]="74637";
        verified["00720"]="41917";
        verified["41671"]="83174";
        verified["00012"]="61325";
        verified["18769"]="27833";
        verified["09994"]="72940";
        verified["17663"]="50175";
        verified["36443"]="23819";
        verified["01450"]="40944";
        verified["11900"]="77162";
        verified["26546"]="67673";
        verified["08980"]="05887";
        verified["09505"]="24967";
        verified["38852"]="22504";
        verified["07391"]="31743";
        verified["24904"]="56126";
        verified["42414"]="13061";
        verified["40210"]="18481";
        verified["34221"]="56213";
        verified["09113"]="33692";
        verified["14515"]="05710";
        verified["06719"]="25026";
        verified["22951"]="23484";
        verified["20971"]="50431";
        verified["12138"]="19983";
        verified["06628"]="36695";
        verified["22993"]="87866";
        verified["05195"]="48169";
        verified["38445"]="48289";
        verified["17384"]="49134";
        verified["00219"]="88567";
        verified["18308"]="82297";
        verified["04400"]="31290";
        verified["01487"]="95232";
        verified["19512"]="95202";
        verified["39570"]="50600";
        verified["09062"]="73965";
        verified["17902"]="59707";
        verified["37447"]="09493";
        verified["19559"]="88112";
        verified["42571"]="96414";
        verified["04080"]="46030";
        verified["38766"]="63417";
        verified["14582"]="67980";
        verified["17392"]="22933";
        verified["25022"]="21167";
        verified["26614"]="06429";
        verified["26131"]="91713";
        verified["38000"]="20658";
        verified["20183"]="44855";
        verified["09595"]="58520";
        verified["29227"]="14380";
        verified["01851"]="36476";
        verified["06421"]="20454";
        verified["07572"]="98463";
        verified["34270"]="97141";
        verified["39013"]="29668";
        verified["05830"]="07745";
        verified["36959"]="46636";
        verified["14556"]="77449";
        verified["19993"]="20167";
        verified["13494"]="01080";
        verified["35161"]="84758";
        verified["02670"]="98118";
        verified["21222"]="78275";
        verified["27238"]="48821";
        verified["29012"]="84172";
        verified["08905"]="00109";
        verified["05672"]="81873";
        verified["07573"]="97174";
        verified["13820"]="13158";
        verified["33655"]="62290";
        verified["34396"]="99533";
        verified["05937"]="74961";
        verified["21696"]="62578";
        verified["41991"]="82743";
        verified["19481"]="34839";
        verified["06413"]="98566";
        verified["06234"]="94646";
        verified["12624"]="06908";
        verified["08257"]="64598";
        verified["10306"]="80608";
        verified["03238"]="68861";
        verified["03294"]="51370";
        verified["16134"]="62104";
        verified["31152"]="51029";
        verified["04731"]="71912";
        verified["24106"]="84861";
        verified["31245"]="52846";
        verified["41214"]="92865";
        verified["02515"]="21371";
        verified["06063"]="46570";
        verified["32829"]="36404";
        verified["32560"]="91202";
        verified["05175"]="76627";
        verified["40963"]="58708";
        verified["39732"]="99399";
        verified["30740"]="20138";
        verified["08743"]="39517";
        verified["40899"]="31324";
        verified["20613"]="97813";
        verified["09466"]="58910";
        verified["21750"]="19919";
        verified["28993"]="43837";
        verified["41409"]="14976";
        verified["35475"]="62097";
        verified["40068"]="68431";
        verified["35190"]="54938";
        verified["38096"]="43966";
        verified["00426"]="29488";
        verified["10747"]="44999";
        verified["29697"]="59850";
        verified["08706"]="46886";
        verified["03056"]="77477";
        verified["35752"]="92924";
        verified["12515"]="31436";
        verified["41523"]="46829";
        verified["23813"]="19160";
        verified["28727"]="44690";
        verified["15010"]="49882";
        verified["19789"]="28730";
        verified["29288"]="99487";
        verified["16096"]="65735";
        verified["41647"]="40863";
        verified["08450"]="46096";
        verified["14605"]="47444";
        verified["09996"]="55248";
        verified["40961"]="18829";
        verified["28603"]="96051";
        verified["08622"]="36746";
        verified["42824"]="20403";
        verified["01587"]="36187";
        verified["32371"]="90597";
        verified["18207"]="56595";
        verified["12585"]="89003";
        verified["16338"]="26639";
        verified["02613"]="83306";
        verified["23684"]="16929";
        verified["18458"]="60851";
        verified["04515"]="20650";
        verified["33513"]="32993";
        verified["13282"]="73856";
        verified["18223"]="77695";
        verified["02671"]="59500";
        verified["01138"]="53856";
        verified["01450"]="51280";
        verified["16423"]="37466";
        verified["03518"]="38399";
        verified["33439"]="49473";
        verified["41157"]="15034";
        verified["03199"]="22627";
        verified["31212"]="48944";
        verified["18954"]="34562";
        verified["04044"]="42840";
        verified["05116"]="08273";
        verified["36521"]="39191";
        verified["39469"]="04231";
        verified["03136"]="87205";
        verified["00579"]="59659";
        verified["17934"]="89743";
        verified["41169"]="02042";
        verified["02725"]="04193";
        verified["27342"]="69841";
        verified["33042"]="75093";
        verified["29282"]="11905";
        verified["23853"]="21534";
        verified["14373"]="61006";
        verified["35802"]="79254";
        verified["11982"]="03306";
        verified["27754"]="24478";
        verified["09533"]="69540";
        verified["40953"]="97810";
        verified["20221"]="00279";
        verified["02928"]="68774";
        verified["33641"]="02411";
        verified["14144"]="64140";
        verified["28520"]="33966";
        verified["29313"]="90095";
        verified["32763"]="70097";
        verified["20575"]="19837";
        verified["02288"]="64195";
        verified["37934"]="27128";
        verified["10273"]="84234";
        verified["38385"]="98046";
        verified["16290"]="42256";
        verified["19405"]="43689";
        verified["16713"]="04977";
        verified["15793"]="65041";
        verified["10326"]="93945";
        verified["08375"]="63349";
        verified["30367"]="60927";
        verified["10284"]="13087";
        verified["07484"]="99181";
        verified["11313"]="12268";
        verified["18345"]="29952";
        verified["09942"]="60360";
        verified["30296"]="90293";
        verified["40943"]="85911";
        verified["24634"]="89279";
        verified["32557"]="97487";
        verified["20666"]="46235";
        verified["19513"]="45921";
        verified["21715"]="44429";
        verified["16808"]="29708";
        verified["41610"]="18209";
        verified["14904"]="84431";
        verified["32437"]="90183";
        verified["32224"]="51030";
        verified["21774"]="17204";
        verified["04258"]="85690";
        verified["28633"]="25959";
        verified["06847"]="79227";
        verified["32385"]="41728";
        verified["21358"]="76433";
        verified["01080"]="35616";
        verified["00851"]="66608";
        verified["24796"]="56152";
        verified["36684"]="98101";
        verified["31094"]="08022";
        verified["14567"]="13508";
        verified["06198"]="47823";
        verified["24106"]="14738";
        verified["23381"]="79881";
        verified["27935"]="33227";
        verified["35422"]="96629";
        verified["00212"]="11257";
        verified["04774"]="04102";
        verified["20092"]="80630";
        verified["35966"]="87909";
        verified["18763"]="39869";
        verified["33861"]="26866";
        verified["38235"]="15929";
        verified["09342"]="22069";
        verified["10489"]="13255";
        verified["29778"]="42942";
        verified["41339"]="46216";
        verified["11111"]="96752";
        verified["29558"]="54734";
        verified["41782"]="92321";
        verified["30584"]="76622";
        verified["30168"]="01323";
        verified["15188"]="87908";
        verified["22068"]="08886";
        verified["01036"]="79099";
        verified["20784"]="02038";
        verified["32964"]="77521";
        verified["03930"]="31402";
        verified["37330"]="78716";
        verified["36596"]="01879";
        verified["34603"]="98753";
        verified["34837"]="49743";
        verified["16400"]="21068";
        verified["05268"]="28045";
        verified["06791"]="74988";
        verified["12000"]="40666";
        verified["20962"]="65766";
        verified["37833"]="55515";
        verified["37676"]="43995";
        verified["31037"]="77135";
        verified["30948"]="29273";
        verified["39784"]="93055";
        verified["20754"]="21131";
        verified["06296"]="12294";
        verified["06501"]="33356";
        verified["39584"]="12808";
        verified["36107"]="24416";
        verified["16527"]="83283";
        verified["38109"]="18654";
        verified["40915"]="47383";
        verified["02126"]="33718";
        verified["02628"]="94202";
        verified["08347"]="90293";
        verified["32778"]="40193";
        verified["22125"]="61470";
        verified["15013"]="48042";
        verified["05162"]="32835";
        verified["36752"]="71049";
        verified["33615"]="94177";
        verified["13962"]="59119";
        verified["10523"]="62103";
        verified["12511"]="81720";
        verified["35130"]="22687";
        verified["28402"]="16155";
        verified["33199"]="94426";
        verified["31039"]="33226";
        verified["31406"]="56459";
        verified["26278"]="89768";
        verified["02192"]="25875";
        verified["36358"]="32937";
        verified["30800"]="02164";
        verified["32882"]="32551";
        verified["37911"]="43105";
        verified["21736"]="01853";
        verified["06893"]="17268";
        verified["42624"]="70687";
        verified["17996"]="61250";
        verified["15852"]="00389";
        verified["13513"]="47957";
        verified["29052"]="36719";
        verified["31428"]="64425";
        verified["40120"]="49159";
        verified["36226"]="98882";
        verified["08121"]="17520";
        verified["36350"]="59213";
        verified["23162"]="95193";
        verified["27017"]="90873";
        verified["05655"]="35817";
        verified["21303"]="15710";
        verified["34582"]="69372";
        verified["34404"]="88900";
        verified["36016"]="22080";
        verified["29822"]="61464";
        verified["31536"]="34232";
        verified["15655"]="09193";
        verified["16283"]="83718";
        verified["24648"]="07335";
        verified["34820"]="01547";
        verified["22995"]="55433";
        verified["13014"]="03316";
        verified["24339"]="40199";
        verified["20557"]="70050";
        verified["00696"]="10449";
        verified["41527"]="38803";
        verified["40512"]="20764";
        verified["17816"]="33474";
        verified["22288"]="72578";
        verified["17806"]="24584";
        verified["26515"]="27575";
        verified["15588"]="75442";
        verified["41881"]="07805";
        verified["21030"]="81286";
        verified["23953"]="45896";
        verified["26747"]="20187";
        verified["05555"]="69080";
        verified["13965"]="37323";
        verified["41249"]="45100";
        verified["41679"]="59227";
        verified["03416"]="52408";
        verified["22783"]="47282";
        verified["02773"]="50232";
        verified["19581"]="47010";
        verified["23294"]="98422";
        verified["15108"]="30911";
        verified["12634"]="39259";
        verified["13627"]="79702";
        verified["13574"]="80304";
        verified["28149"]="41990";
        verified["05379"]="49699";
        verified["36035"]="69060";
        verified["07258"]="85741";
        verified["00241"]="20153";
        verified["20036"]="19097";
        verified["37355"]="93195";
        verified["36665"]="14706";
        verified["35662"]="11347";
        verified["02491"]="00130";
        verified["39304"]="78885";
        verified["37403"]="37976";
        verified["32444"]="11064";
        verified["02561"]="41984";
        verified["19648"]="22720";
        verified["23400"]="53841";
        verified["01225"]="67936";
        verified["00575"]="37723";
        verified["26793"]="20883";
        verified["38796"]="80120";
        verified["35199"]="08387";
        verified["32075"]="08101";
        verified["11525"]="54752";
        verified["37645"]="72826";
        verified["12892"]="92686";
        verified["10231"]="51410";
        verified["41408"]="79147";
        verified["05871"]="71950";
        verified["05784"]="62443";
        verified["37447"]="60454";
        verified["24546"]="02539";
        verified["04993"]="68620";
        verified["31974"]="12073";
        verified["36431"]="59118";
        verified["36842"]="70137";
        verified["23628"]="18940";
        verified["34554"]="00851";
        verified["30880"]="44320";
        verified["01381"]="95602";
        verified["38356"]="19942";
        verified["38206"]="33202";
        verified["01091"]="08463";
        verified["38488"]="57943";
        verified["23951"]="43690";
        verified["05998"]="11002";
        verified["42488"]="48589";
        verified["20447"]="84584";
        verified["39089"]="96389";
        verified["08400"]="85221";
        verified["06108"]="63051";
        verified["20237"]="73148";
        verified["04941"]="40409";
        verified["31970"]="77623";
        verified["11482"]="42504";
        verified["02947"]="11177";
        verified["30658"]="60735";
        verified["31134"]="77769";
        verified["06024"]="33291";
        verified["08540"]="76233";
        verified["18264"]="54832";
        verified["28392"]="03803";
        verified["19523"]="25002";
        verified["31048"]="69611";
        verified["16765"]="83888";
        verified["17179"]="50610";
        verified["16672"]="69873";
        verified["37589"]="68924";
        verified["39457"]="68647";
        verified["02789"]="84120";
        verified["04127"]="92342";
        verified["26218"]="63765";
        verified["32608"]="86484";
        verified["03533"]="63493";
        verified["02112"]="60003";
        verified["22068"]="13013";
        verified["39737"]="72112";
        verified["25562"]="46294";
        verified["00880"]="34583";
        verified["03310"]="31402";
        verified["01119"]="73423";
        verified["08427"]="05633";
        verified["08990"]="34929";
        verified["14255"]="81291";
        verified["26138"]="07307";
        verified["22087"]="23226";
        verified["14483"]="57684";
        verified["06699"]="03984";
        verified["39997"]="68796";
        verified["42395"]="83980";
        verified["33337"]="17188";
        verified["21083"]="02197";
        verified["04551"]="19656";
        verified["13020"]="00194";
        verified["19251"]="17727";
        verified["34792"]="78411";
        verified["19025"]="46659";
        verified["06363"]="68097";
        verified["40083"]="63779";
        verified["25629"]="24518";
        verified["03569"]="80171";
        verified["15791"]="21805";
        verified["04697"]="98229";
        verified["33337"]="33176";
        verified["31793"]="56131";
        verified["23656"]="76861";
        verified["35492"]="59950";
        verified["18648"]="00370";
        verified["05131"]="42283";
        verified["18213"]="71373";
        verified["27003"]="39909";
        verified["32579"]="17153";
        verified["02542"]="48046";
        verified["34310"]="96059";
        verified["12628"]="93071";
        verified["39128"]="12294";
        verified["39139"]="08878";
        verified["35040"]="66168";
        verified["13544"]="59044";
        verified["23924"]="37661";
        verified["28499"]="05216";
        verified["04384"]="09693";
        verified["04496"]="65778";
        verified["26443"]="44766";
        verified["36383"]="58065";
        verified["01298"]="99025";
        verified["19815"]="03119";
        verified["02440"]="93321";
        verified["00700"]="61279";
        verified["36678"]="77192";
        verified["26016"]="05521";
        verified["34718"]="86802";
        verified["11583"]="52133";
        verified["27829"]="17448";
        verified["26459"]="95216";
        verified["19598"]="71583";
        verified["18194"]="84316";
        verified["18633"]="63215";
        verified["33563"]="35219";
        verified["01483"]="92691";
        verified["19475"]="56446";
        verified["24511"]="28601";
        verified["27780"]="90284";
        verified["18098"]="68946";
        verified["15131"]="11563";
        verified["09333"]="12079";
        verified["14765"]="04839";
        verified["23461"]="08903";
        verified["34545"]="63106";
        verified["12777"]="39567";
        verified["25526"]="42644";
        verified["40010"]="02830";
        verified["41399"]="26118";
        verified["20400"]="65246";
        verified["27834"]="48102";
        verified["01226"]="14535";
        verified["28913"]="44089";
        verified["41931"]="55628";
        verified["15614"]="66643";
        verified["40418"]="22239";
        verified["41988"]="94377";
        verified["29163"]="12043";
        verified["37090"]="31992";
        verified["25877"]="59410";
        verified["16238"]="96766";
        verified["37129"]="81120";
        verified["26547"]="05314";
        verified["20092"]="01183";
        verified["31190"]="58366";
        verified["13946"]="33053";
        verified["11816"]="79450";
        verified["27991"]="50694";
        verified["30522"]="83426";
        verified["12200"]="72449";
        verified["14857"]="13853";
        verified["15441"]="11312";
        verified["29856"]="88118";
        verified["14783"]="26050";
        verified["01598"]="78256";
        verified["04387"]="50746";
        verified["21260"]="01468";
        verified["02223"]="38850";
        verified["42487"]="09273";
        verified["11357"]="99183";
        verified["27438"]="38531";
        verified["26310"]="79608";
        verified["20179"]="32579";
        verified["33023"]="31976";
        verified["06100"]="08883";
        verified["06508"]="21149";
        verified["05536"]="10090";
        verified["38590"]="90504";
        verified["06501"]="28932";
        verified["04087"]="72775";
        verified["06678"]="47060";
        verified["37911"]="22406";
        verified["13578"]="76778";
        verified["19395"]="37871";
        verified["10133"]="29647";
        verified["01952"]="35271";
        verified["41543"]="72461";
        verified["24244"]="78848";
        verified["08229"]="35625";
        verified["19657"]="72386";
        verified["16375"]="01114";
        verified["32172"]="37620";
        verified["08376"]="75480";
        verified["17947"]="69993";
        verified["10805"]="36609";
        verified["19552"]="92929";
        verified["05894"]="29607";
        verified["27902"]="23391";
        verified["40786"]="74252";
        verified["03824"]="19222";
        verified["29271"]="72580";
        verified["32620"]="03089";
        verified["08377"]="52798";
        verified["35593"]="23292";
        verified["07882"]="74434";
        verified["03923"]="35008";
        verified["26710"]="56227";
        verified["14508"]="60672";
        verified["13351"]="23884";
        verified["30156"]="76668";
        verified["20450"]="54025";
        verified["27919"]="92609";
        verified["15284"]="67788";
        verified["38648"]="33679";
        verified["36428"]="09930";
        verified["24296"]="01951";
        verified["22261"]="92844";
        verified["34537"]="42883";
        verified["01301"]="70076";
        verified["12772"]="12916";
        verified["22482"]="80586";
        verified["26632"]="34666";
        verified["36768"]="57123";
        verified["06128"]="28683";
        verified["29204"]="93223";
        verified["06651"]="34918";
        verified["14590"]="80493";
        verified["03082"]="54442";
        verified["18275"]="35305";
        verified["34099"]="77041";
        verified["23398"]="86009";
        verified["37651"]="08125";
        verified["39826"]="06546";
        verified["27129"]="09037";
        verified["27098"]="80971";
        verified["13517"]="07136";
        verified["04342"]="83686";
        verified["17610"]="29465";
    }
}

