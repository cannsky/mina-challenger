import { AccountUpdate, Bool, Field, MerkleMap, MerkleTree, Mina, Poseidon, PrivateKey, UInt64 } from "o1js";
import { MessageChallenge } from "./MessageChallenge.js";


describe("Message Challenge Test", () => {
    // Local chain to test
    const localChain = Mina.LocalBlockchain({ proofsEnabled: false });
    // Activate the local blockchain
    Mina.setActiveInstance(localChain);
    // Create private key for the contract
    const contractPrivateKey = PrivateKey.random();
    // Create an admin
    const admin = localChain.testAccounts[0];
    // Create a user
    const user = localChain.testAccounts[1];
    // Create other user
    const otherUser = localChain.testAccounts[2];
    // Create address map
    const testAddressMap = new MerkleMap();
    // Create merkle map
    const testMessageMap = new MerkleMap();
    // Create Message Challenge
    const messageChallenge = new MessageChallenge(contractPrivateKey.toPublicKey());

    it("can compile contract", async () => {
        // Compile the message challenge
        await MessageChallenge.compile();
    });

    it("can deploy the contract", async () => {
        // Create a transaction to deploy the contract
        const tx = await Mina.transaction(admin.publicKey, () => {
            messageChallenge.deploy();
            AccountUpdate.fundNewAccount(admin.publicKey);
        });
        // Wait transaction to be proved
        await tx.prove();
        // Sign the transaction
        tx.sign([admin.privateKey, contractPrivateKey]);
        // Send the transaction
        await tx.send();
        // Get contract admin
        const contractAdminAddress = messageChallenge.adminAddress.get();
        // Check if the admin is correctly set
        expect(contractAdminAddress).toEqual(admin.publicKey);
    });

    it("admin address can store address", async () => {

        // TRY REAL ADMIN

        // Create user hash
        const userHash = await Poseidon.hash(user.publicKey.toFields());
        // Create a transaction to store and address
        const tx = await Mina.transaction(admin.publicKey, () => {
            const addressWitness = testAddressMap.getWitness(userHash);
            messageChallenge.storeAddress(user.publicKey, addressWitness);
        });
        // Wait transaction to be proved
        await tx.prove();
        // Sign the transaction
        tx.sign([admin.privateKey]);
        // Send the transaction
        await tx.send();
        // Add user hash to test address map for comparing the contract address map
        testAddressMap.set(userHash, Bool(true).toField());
        // Get new address root from contract
        const contractAddressRoot = messageChallenge.addressRoot.get();
        // Get contract address count from contract
        const contractAddressCount = messageChallenge.addressCount.get();
        // Check if the admin map root is correctly set
        expect(contractAddressRoot).toEqual(testAddressMap.getRoot());
        // Check if the address count is increased by 1
        expect(contractAddressCount).toEqual(UInt64.from(1));

        // TRY NON-ADMIN

        try {
            // Create a transaction to store and address
            const otherTX = await Mina.transaction(user.publicKey, () => {
                const addressWitness = testAddressMap.getWitness(userHash);
                messageChallenge.storeAddress(user.publicKey, addressWitness);
            });
            // This line shouldn't work
            expect(true).toEqual(false);
        }
        catch {
            // Error thrown as expected
            expect(true).toEqual(true);
        }
    });

    it("eligable address can add message", async () => {

        // TRY ELIGABLE USER

        // Create user hash
        const userHash = await Poseidon.hash(user.publicKey.toFields());
        // Create empty field
        const messageArray = Field.empty().toBits();
        // Set flag 1 to true
        messageArray[249] = Bool(true);
        // Create the message
        const message = Field.fromBits(messageArray);
        // Create a transaction to add message
        const tx = await Mina.transaction(user.publicKey, () => {
            const addressWitness = testAddressMap.getWitness(userHash);
            const messageWitness = testMessageMap.getWitness(userHash);
            messageChallenge.depositMessage(message, messageWitness, addressWitness);
        });
        // Wait transaction to be proved
        await tx.prove();
        // Sign the transaction
        tx.sign([user.privateKey]);
        // Send the transaction
        await tx.send();
        // Add user message to test message map for comparing the contract message map
        testMessageMap.set(userHash, message);
        // Get new message root from contract
        const contractMessageRoot = messageChallenge.messageRoot.get();
        // Get contract message count from contract
        const contractMessageCount = messageChallenge.messageCount.get();
        // Check if the admin map root is correctly set
        expect(contractMessageRoot).toEqual(testMessageMap.getRoot());
        // Check if the address count is increased by 1
        expect(contractMessageCount).toEqual(UInt64.from(1));

        // TRY NON-ELIGABLE USER

        // Create user hash
        const otherUserHash = await Poseidon.hash(otherUser.publicKey.toFields());
        try {
            // Create a transaction to store and address
            const otherTX = await Mina.transaction(otherUser.publicKey, () => {
                const addressWitness = testAddressMap.getWitness(otherUserHash);
                const messageWitness = testMessageMap.getWitness(otherUserHash);
                messageChallenge.depositMessage(message, messageWitness, addressWitness);
            });
            // This line shouldn't work
            expect(true).toEqual(false);
        }
        catch {
            // Error thrown as expected
            expect(true).toEqual(true);
        }
    });

    
    it("can check message and sender of message", async () => {

        // TRY ELIGABLE USER

        // Create user hash
        const userHash = await Poseidon.hash(user.publicKey.toFields());
        // Create empty field
        const messageArray = Field.empty().toBits();
        // Set flag 1 to true
        messageArray[249] = Bool(true);
        // Create the message
        const message = Field.fromBits(messageArray);
        // Create a transaction to add message
        const tx = await Mina.transaction(user.publicKey, () => {
            const messageWitness = testMessageMap.getWitness(userHash);
            messageChallenge.checkMessage(user.publicKey, message, messageWitness);
        });
        // Wait transaction to be proved
        await tx.prove();
        // Sign the transaction
        tx.sign([user.privateKey]);
        // Send the transaction
        await tx.send();

        // TRY NON-ELIGABLE USER

        const otherUserHash = await Poseidon.hash(otherUser.publicKey.toFields());
        try {
            // Create a transaction to store and address
            const otherTx = await Mina.transaction(otherUser.publicKey, () => {
                const messageWitness = testMessageMap.getWitness(otherUserHash);
                messageChallenge.checkMessage(otherUser.publicKey, message, messageWitness);
            });
            // This line shouldn't work
            expect(true).toEqual(false);
        }
        catch {
            // Error thrown as expected
            expect(true).toEqual(true);
        }
    });

});