library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

entity hello is
end hello;

architecture Behavioral of hello is
begin
    process
    begin
        report "Hello from VHDL";
        wait;
    end process;
end Behavioral;
