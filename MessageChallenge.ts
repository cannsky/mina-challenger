import { 
    AccountUpdate, 
    Bool, 
    DeployArgs, 
    Field, 
    MerkleMap, 
    MerkleMapWitness, 
    Permissions,
    Poseidon,
    Provable,
    PublicKey,
    SmartContract,
    State,
    UInt64,
    method,
    state
} from "o1js";

export class MessageChallenge extends SmartContract {
    
    @state(PublicKey) adminAddress = State<PublicKey>();

    @state(UInt64) messageCount = State<UInt64>();

    @state(UInt64) addressCount = State<UInt64>();

    @state(Field) addressRoot = State<Field>();

    @state(Field) messageRoot = State<Field>();

    deploy(deployArgs?: DeployArgs) {
        super.deploy(deployArgs);
        this.account.permissions.set({
            ...Permissions.allImpossible(),
            access: Permissions.proof(),
            editState: Permissions.proof()
        });
    }

    init() {
        super.init();
        // Make sure that, this is signed by this sender.
        AccountUpdate.createSigned(this.sender);
        // Create empty map
        const map = new MerkleMap()
        this.adminAddress.set(this.sender);
        this.addressCount.set(UInt64.zero);
        this.addressRoot.set(map.getRoot());
        this.messageRoot.set(map.getRoot());
    }

    @method storeAddress(address: PublicKey, addressWitness: MerkleMapWitness) {
        // Make sure that, this is signed by this sender.
        AccountUpdate.createSigned(this.sender);
        // Check if the admin address value is same in onchain
        const adminAddress = this.adminAddress.getAndRequireEquals();
        // Check if the count value is same in onchain
        const addressCount = this.addressCount.getAndRequireEquals();
        // Check if the root value is same in onchain
        const addressRoot = this.addressRoot.getAndRequireEquals();
        // Make sure that, this is sent by the admin.
        adminAddress.assertEquals(this.sender);
        // Make sure that, there is enough space on the limit (100)
        addressCount.assertLessThanOrEqual(UInt64.from(100), "There are 100 addresses stored, more cannot be added");
        // Hash the address given
        const hash = Poseidon.hash(address.toFields());
        // Check if user is eligible or not
        const [computedRoot, computedHash] = addressWitness.computeRootAndKey(Bool(false).toField());
        // Check if hash is equals to the computed hash
        hash.assertEquals(computedHash, "Hashes needs to be same.");
        // Check if the root is equals to the computed root
        addressRoot.assertEquals(computedRoot, "Roots needs to be same.");
        // Compute root for saving the address
        const [newRoot] = addressWitness.computeRootAndKey(Bool(true).toField());
        // Increase address count by 1
        this.addressCount.set(addressCount.add(1));
        // Save the address
        this.addressRoot.set(newRoot);
    }

    @method depositMessage(message: Field, messageWitness: MerkleMapWitness, addressWitness: MerkleMapWitness) {
        // Make sure that, this is signed by this sender.
        AccountUpdate.createSigned(this.sender);
        // Check if the root value is same in onchain
        const addressRoot = this.addressRoot.getAndRequireEquals();
        // Check if the message root value is same in onchain
        const messageRoot = this.messageRoot.getAndRequireEquals();
        // Get message count
        const messageCount = this.messageCount.getAndRequireEquals();
        // Hash the address given
        const hash = Poseidon.hash(this.sender.toFields());
        // Check if user is eligible or not
        const [computedRoot, computedHash] = addressWitness.computeRootAndKey(Bool(true).toField());
        // Check if hash is equals to the computed hash
        hash.assertEquals(computedHash, "Hashes needs to be same.");
        // Check if the root is equals to the computed root
        addressRoot.assertEquals(computedRoot, "Roots needs to be same.");
        // compute the message witness
        const [computedMessageRoot, computedSenderHash] = messageWitness.computeRootAndKey(Bool(false).toField());
        // Check if the hashes are equal
        hash.assertEquals(computedSenderHash);
        // Check if the roots are equal
        messageRoot.assertEquals(computedMessageRoot);
        // Create message array
        const messageArray = message.toBits();
        // Last 6 bits are the flags.
        // If the first flag is true all other flags must be false
        Provable.if(
            messageArray[249], 
            messageArray[250].or(messageArray[251]).or(messageArray[252]).or(messageArray[253]).or(messageArray[254]), 
            Bool(false)
        ).assertFalse();
        // If flag 2 is true than flag 3 must be true
        Provable.if(messageArray[250], messageArray[251], Bool(true)).assertTrue();
        // If flag 4 is true than flag 5 and flag 6 must be false
        Provable.if(messageArray[252], messageArray[253].or(messageArray[254]), Bool(false)).assertFalse();
        // Create a new message root
        const [newMessageRoot] = messageWitness.computeRootAndKey(message);
        // Increment message count by 1
        this.messageCount.set(messageCount.add(1));
        // Set new message root
        this.messageRoot.set(newMessageRoot);
    }

    @method checkMessage(senderAddress: PublicKey, message: Field, messageWitness: MerkleMapWitness) {
        // Check if the message root value is same in onchain
        const messageRoot = this.messageRoot.getAndRequireEquals();
        // Hash the address given
        const hash = Poseidon.hash(senderAddress.toFields());
        // compute the message witness
        const [computedMessageRoot, computedSenderHash] = messageWitness.computeRootAndKey(message);
        // Assert if there is a problem
        messageRoot.assertEquals(computedMessageRoot, "Hashes needs to be same.");
        // Check if the root is equals to the computed root
        hash.assertEquals(computedSenderHash, "Roots needs to be same.");
        // Return if the given sender address added the given message
        return messageRoot.equals(computedMessageRoot).and(hash.equals(computedSenderHash));
    }
}