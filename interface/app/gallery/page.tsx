"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { MeiliSearch } from 'meilisearch';
import MiniCard from '@/comp/solution/MiniCard';
import Masonry from 'react-masonry-css';
import { fetchQueryLikedSolutions } from '@/lib/actions';
import { FaSearch } from 'react-icons/fa';
import SearchBar from './SearchBar';

interface MasonryGalleryProps {
    solutions: any[];
    likedSolutions: { [key: string]: boolean };
}

const MasonryGallery: React.FC<MasonryGalleryProps> = ({ solutions, likedSolutions }) => {
    const columns = Math.min(5, solutions.length);
    const breakpointColumnsObj = {
        default: columns,
        1600: Math.min(4, solutions.length),
        1200: Math.min(3, solutions.length),
        800: Math.min(2, solutions.length),
        640: 1,
    };

    const [likes, setLikes] = useState({});
    useEffect(() => {
        setLikes(likedSolutions);
    }, [likedSolutions]);

    return (
        <div className="flex justify-center p-4 w-full">
            <Masonry
                breakpointCols={breakpointColumnsObj}
                className="flex"
                columnClassName="masonry-grid_column flex flex-col"
            >
                {solutions.map((solution, index) => (
                    <MiniCard
                        key={index}
                        content={solution}
                        index={index}
                        isLiked={likes[solution.id]}
                    />
                ))}
            </Masonry>
        </div>
    );
};

const Gallery = () => {
    const apiUrl = process.env.API_URL.replace(':5000', ':7700/');
    const [loading, setLoading] = useState(true);
    const [solutions, setSolutions] = useState([]);
    const [likedSolutions, setLikedSolutions] = useState({});
    const [error, setError] = useState(null);

    const [query, setQuery] = useState('');
    const [page, setPage] = useState(1);
    const [hasMore, setHasMore] = useState(true);

    const scrollContainerRef = useRef(null);

    const client = useMemo(() => new MeiliSearch({ host: apiUrl }), [apiUrl]);
    const fetchSolutions = useCallback(async (searchQuery = '', pageNumber = 1) => {
        setLoading(true);
        try {
            const index = client.index('solution_id');
            // const keywords = searchQuery.trim().split(/\s+/);

            // await index.updateSortableAttributes(['timestamp']);
            const searchResults = await index.search(searchQuery, {
                limit: 10,
                offset: (pageNumber - 1) * 10,
                sort: ['timestamp:desc'],
            });
            if (searchResults.hits.length > 0) {
                const modifiedResults = searchResults.hits.map((hit) => ({
                    ...hit,
                    id: hit._id,
                    _id: undefined,
                }));

                setSolutions((prevPapers) => (pageNumber === 1 ? modifiedResults : [...prevPapers, ...modifiedResults]));

                const solutionIds = modifiedResults.map(solution => solution.id);
                const likedStatuses = await fetchQueryLikedSolutions(solutionIds);
                console.log(likedStatuses);

                const newLikedStates = likedStatuses.reduce((acc, { solution_id, isLiked }) => {
                    acc[solution_id] = isLiked;
                    return acc;
                }, {});
                setLikedSolutions(prevLiked => ({
                    ...prevLiked,
                    ...newLikedStates,
                }));

                setHasMore(true);
            } else {
                setHasMore(false);
            }
        } catch (error) {
            setError('Error fetching papers');
        } finally {
            setLoading(false);
        }
    }, [client]);

    useEffect(() => {
        fetchSolutions(query, page);
    }, [query, page, fetchSolutions]);

    const handleSearch = (e) => {
        e.preventDefault();
        setPage(1);
        setSolutions([]);
        fetchSolutions(query, 1);
    };

    useEffect(() => {
        const handleScroll = () => {
            if (scrollContainerRef.current) {
                const { scrollTop, scrollHeight, clientHeight } = scrollContainerRef.current;
                if (scrollTop + clientHeight >= scrollHeight - 50 && !loading && hasMore) {
                    setPage((prevPage) => prevPage + 1);
                }
            }
        };

        const container = scrollContainerRef.current;
        container?.addEventListener('scroll', handleScroll);
        return () => container?.removeEventListener('scroll', handleScroll);
    }, [loading, hasMore]);

    return (
        <div
            ref={scrollContainerRef}
            style={{ height: '100vh', overflowY: 'auto', marginLeft: '15rem' }}
        >
            <div className="flex justify-center mt-8">
                <header className="mb-6 text-center w-full">
                <SearchBar onSearch={handleSearch} />
                </header>
            </div>

            {loading && page === 1 ? (
                <div style={{ fontSize: '24px', marginTop: '100px', textAlign: 'center' }}>
                    Loading...
                </div>
            ) : error ? (
                <div style={{ color: 'red', textAlign: 'center', marginTop: '100px' }}>
                    {error}
                </div>
            ) : (
                <div>
                    <MasonryGallery solutions={solutions} likedSolutions={likedSolutions} />
                    {loading && page > 1 && (
                        <div style={{ textAlign: 'center', marginTop: '1rem' }}>Loading more...</div>
                    )}
                </div>
            )}
        </div>
    );
};

export default Gallery;
