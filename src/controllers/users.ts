import { Request, Response } from 'express';

export const getUsers = (req: Request, res: Response) => {
    // Just a mock example
    const users = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' },
    ];
    res.json(users);
}
