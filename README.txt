Project 4: Authorization Checks
Ryan Gleason

Requirements given to me: 
(a) Prevent any information flows from objects owned by subject T1 to subject T3
(b) Other information flows are allowed

a.)
I achieved this by setting the hooks at the beginning of each function.
In my policy-input.txt you will see all of the different authorized policies.
The only combinations that are left out are T3:T1:A1, T3:T1:A2, T3:T1:A3. Any 
information flows from objects owned by subject T1 to subject T3 will be 
prevented because of this. 
	
b.)
All other inputs are allowed. 

I commented out hooks that would be redundant. Since the hook is placed at the
beginning of the function, any hook after that, but within the scope of the 
function would be redundant. 
