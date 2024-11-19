import React, { useState } from 'react';
import { FaSearch } from 'react-icons/fa';

const SearchBar = ({ onSearch }) => {
    const [query, setQuery] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        onSearch(query);
    };

    return (
        <form onSubmit={handleSubmit} className="flex justify-center">
            <div className="relative w-[80%] max-w-3xl">
                <span className="absolute left-4 top-1/2 transform -translate-y-1/2 text-neutral-400">
                    <FaSearch />
                </span>
                <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Search Solutions"
                    className="w-full pl-12 pr-4 py-3 text-lg border border-neutral-700 rounded-lg bg-neutral-800 text-neutral-100 outline-none shadow focus:ring focus:ring-neutral-700 focus:border-neutral-500 transition-all duration-300"
                />
            </div>
        </form>
    );
};

export default SearchBar;