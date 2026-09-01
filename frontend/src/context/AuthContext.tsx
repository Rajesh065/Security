import React, { createContext, useContext, useState } from 'react';

interface AuthContextType {
  role: string;
  setRole: (r: string) => void;
  commanderName: string;
  team: string;
  defconLevel: number;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [role, setRole] = useState('INCIDENT_COMMANDER');
  return (
    <AuthContext.Provider value={{
      role,
      setRole,
      commanderName: 'Viktor Vance (Lead Commander)',
      team: 'Global Incident Response Team',
      defconLevel: 4
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const c = useContext(AuthContext);
  if (!c) throw new Error('useAuth error');
  return c;
};
