# The Rights Delegation Proxy: An Approach for Delegations in the Solid Dataspace

Delegations of responsibilities, e.g. acting on behalf of someone else, is an everyday task. With the rise of dataspaces, we need techniques to represent delegations among agents in dataspaces as well. While the Social Linked Data project (Solid) already changed the way of data sharing and introduced dataspaces built on existing Web standards, the question of representing, monitoring, and enacting sophisticated delegations is still open.

We propose the Rights Delegation Proxy (RDP) to check and execute delegations in dataspaces building on the Social Linked Data project (Solid). The Rights Delegation Proxy ensures privacy by keeping delegation details hidden and validates delegated actions against policies for legitimacy.
We show our implemented architecture in an exemplary loan contract scenario, where a person signs a contract on behalf of a company with a bank. Additionally, we analyze our architecture for privacy and legitimacy using formal models. 

Goals for the delegation process:
1. The affiliate $A$ will never get to know a client's name, regardless of whether the client was a delegate or not according to the delegator.
2. For all messages a client sends to the affiliate (possibly using the RDP), the delegator's policies have been validated.
3. For all messages a client sends to the affiliate (possibly using the RDP), the client will receive a response afterwards.

Contents:
* /implementation/ - contains our RDP implementation
