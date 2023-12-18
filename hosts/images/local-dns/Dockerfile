FROM handsonsecurity/seed-server:bind

# Copy the configuration file for the local DNS server
COPY named.conf           /etc/bind/
COPY named.conf.options   /etc/bind/

RUN echo "export PS1='$(whoami)@localdns: [$(pwd)] $ '" >> $HOME/.bashrc
CMD service named start && tail -f /dev/null 
